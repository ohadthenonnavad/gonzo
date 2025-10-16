// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/string.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/version.h>
#include "gonzo.h"

#define NETLOG_PORT 7777

static struct socket *sock = NULL;
static struct task_struct *accept_thread = NULL;
static struct socket *client_sock = NULL;
static DEFINE_SPINLOCK(client_lock);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
/* Backport of kernel_sendmsg for older kernels */
static int netlog_sendmsg(struct socket *sock, struct msghdr *msg, struct kvec *vec,
                         size_t num, size_t size)
{
    mm_segment_t oldfs;
    int ret;

    if (sock == NULL || sock->ops == NULL || sock->ops->sendmsg == NULL)
        return -EINVAL;

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    ret = sock->ops->sendmsg(NULL, sock, msg, size);
    set_fs(oldfs);
    return ret;
}
#else
#define netlog_sendmsg kernel_sendmsg
#endif

static int netlog_send(const char *buf, size_t len)
{
    struct msghdr msg = {
        .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL,
    };
    struct kvec vec = {
        .iov_base = (void *)buf,
        .iov_len = len
    };
    int ret = 0;
    
    if (!buf || len == 0) {
        printk(KERN_ERR "Invalid buffer or length in netlog_send\n");
        return -EINVAL;
    }
    
    spin_lock_bh(&client_lock);
    if (client_sock) {
        struct socket *sock = client_sock;
        printk(KERN_DEBUG "Sending %zu bytes to client\n", len);
        
        /* Release lock while sending to avoid holding it during I/O */
        spin_unlock_bh(&client_lock);
        
        ret = kernel_sendmsg(sock, &msg, &vec, 1, len);
        
        spin_lock_bh(&client_lock);
        if (ret < 0) {
            printk(KERN_ERR "Failed to send data to client: %d\n", ret);
            /* On error, close the socket */
            if (client_sock == sock) {
                sock_release(client_sock);
                client_sock = NULL;
            }
        } else if (ret == 0) {
            printk(KERN_DEBUG "Connection closed by peer\n");
            if (client_sock == sock) {
                sock_release(client_sock);
                client_sock = NULL;
            }
            ret = -ECONNRESET;
        } else {
            printk(KERN_DEBUG "Successfully sent %d/%zu bytes to client\n", ret, len);
        }
    } else {
        printk(KERN_DEBUG "No client connected, dropping %zu bytes\n", len);
        ret = -ENOTCONN;
    }
    spin_unlock_bh(&client_lock);
    
    return ret;
}

static int accept_thread_fn(void *data)
{
    struct socket *newsock = NULL;
    int err;
    
    allow_signal(SIGKILL);
    
    printk(KERN_INFO "Netlog accept thread started, waiting for connections...\n");
    
    while (!kthread_should_stop()) {
        struct sock *sk;
        struct inet_sock *inet;
        int yes = 1;
        
        /* Check if socket is still valid */
        if (!sock) {
            printk(KERN_ERR "Netlog: Listening socket is NULL, stopping accept thread\n");
            break;
        }
        
        /* Initialize newsock to NULL */
        newsock = NULL;
        
        /* Accept a new connection */
        err = kernel_accept(sock, &newsock, O_NONBLOCK);
        if (err) {
            if (signal_pending(current)) {
                printk(KERN_INFO "Netlog accept thread received signal, stopping\n");
                break;
            }
            if (err != -EAGAIN) {
                printk(KERN_ERR "Netlog accept error: %d\n", err);
            }
            msleep(1000);
            continue;
        }
        
        /* Verify the accepted socket */
        if (!newsock || !newsock->sk) {
            printk(KERN_ERR "Netlog: Invalid accepted socket\n");
            if (newsock) {
                sock_release(newsock);
            }
            continue;
        }
        
        /* Get socket and address info */
        sk = newsock->sk;
        inet = inet_sk(sk);
        
        printk(KERN_INFO "Netlog connection accepted from %pI4:%d\n", 
               &inet->inet_daddr, ntohs(inet->inet_dport));
        
        /* Configure socket options - no timeouts, non-blocking */
        kernel_setsockopt(newsock, SOL_TCP, TCP_NODELAY, (char *)&yes, sizeof(yes));
        
        /* Set socket to non-blocking mode */
        int flags = O_NONBLOCK;
        kernel_setsockopt(newsock, SOL_SOCKET, SO_SNDTIMEO, (char *)&flags, sizeof(flags));
        kernel_setsockopt(newsock, SOL_SOCKET, SO_RCVTIMEO, (char *)&flags, sizeof(flags));
        
        /* Disable keepalive to prevent timeouts */
        int no = 0;
        kernel_setsockopt(newsock, SOL_SOCKET, SO_KEEPALIVE, (char *)&no, sizeof(no));
        
        /* Update client socket with proper locking */
        spin_lock_bh(&client_lock);
        if (client_sock) {
            struct socket *old_sock = client_sock;
            client_sock = NULL;
            spin_unlock_bh(&client_lock);
            
            /* Close old connection */
            kernel_sock_shutdown(old_sock, SHUT_RDWR);
            sock_release(old_sock);
            
            spin_lock_bh(&client_lock);
        }
        client_sock = newsock;
        spin_unlock_bh(&client_lock);
        
        /* Send welcome message */
        //err = netlog_send(welcome, strlen(welcome));
        //if (err < 0) {
        //    printk(KERN_ERR "Failed to send welcome message: %d\n", err);
        //}
    }
    
    return 0;
}

/**
 * netlog_wait_for_client - Wait for a client to connect
 * 
 * @timeout_sec: Maximum time to wait in seconds
 * 
 * Return: 0 if client connected, -ETIMEDOUT if timeout occurred
 */
int netlog_wait_for_client(unsigned int timeout_sec)
{
    unsigned long timeout = jiffies + timeout_sec * HZ;
    int connected = 0;
    
    printk(KERN_INFO "Waiting for debug client to connect (timeout: %u seconds)...\n", timeout_sec);
    
    while (time_before(jiffies, timeout)) {
        spin_lock_bh(&client_lock);
        if (client_sock != NULL) {
            spin_unlock_bh(&client_lock);
            printk(KERN_INFO "Debug client connected\n");
            connected = 1;
            break;
        }
        spin_unlock_bh(&client_lock);
        
        /* Check if a client connected during our sleep */
        if (client_sock != NULL) {
            printk(KERN_INFO "Debug client connected\n");
            connected = 1;
            break;
        }
        
        /* Only sleep if no client is connected yet */
        msleep(100);
    }
    
    if (!connected) {
        printk(KERN_WARNING "No debug client connected after %u seconds, closing listener\n", timeout_sec);
        if (sock) {
            sock_release(sock);
            sock = NULL;
        }
        return -ETIMEDOUT;
    }
    
    return 0;
}

int netlog_init(void)
{
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(NETLOG_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),  // Listen on all interfaces
    };
    
    int err;
    printk(KERN_INFO "Gonzo debug server starting on port %d\n", NETLOG_PORT);
    
    // Print network configuration for debugging
    printk(KERN_INFO "Network configuration:\n");
    printk(KERN_INFO "- Protocol: TCP\n");
    printk(KERN_INFO "- Port: %d\n", NETLOG_PORT);
    printk(KERN_INFO "- Interface: 0.0.0.0 (all interfaces)\n");
    
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
    /* For kernel 3.10.0 and earlier, use the 4-argument version */
    err = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
#else
    /* For kernel 3.11 and later, use the 5-argument version */
    err = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
#endif
    if (err < 0) {
        printk(KERN_ERR "Failed to create socket: %d\n", err);
        return err;
    }
    
    // Bind the socket
    err = kernel_bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (err < 0) {
        printk(KERN_ERR "Failed to bind socket on port %d: %d\n", 
               NETLOG_PORT, err);
        goto err_sock;
    }

    // Start listening
    err = kernel_listen(sock, 1);
    if (err < 0) {
        printk(KERN_ERR "Failed to listen on socket: %d\n", err);
        goto err_sock;
    }
    
    printk(KERN_INFO "Listening for connections on port %d...\n", NETLOG_PORT);
    printk(KERN_DEBUG "Socket flags: type=%d, state=%d, sk_flags=%lx\n", 
           sock->type, sock->sk->sk_state, sock->flags);
    
    accept_thread = kthread_run(accept_thread_fn, NULL, "gonzo-netlog");
    if (IS_ERR(accept_thread)) {
        err = PTR_ERR(accept_thread);
        accept_thread = NULL;
        goto err_sock;
    }
    
    return 0;
    
err_sock:
    if (sock) {
        sock_release(sock);
        sock = NULL;
    }
    return err;
}

void netlog_exit(void)
{
    /* Stop the accept thread first */
    if (accept_thread) {
        kthread_stop(accept_thread);
        accept_thread = NULL;
    }
    
    /* Handle client socket */
    spin_lock_bh(&client_lock);
    if (client_sock) {
        struct socket *s = client_sock;
        client_sock = NULL;
        spin_unlock_bh(&client_lock);  /* Unlock after clearing client_sock */
        
        /* Shutdown the socket */
        kernel_sock_shutdown(s, SHUT_RDWR);
        
        /* Release the socket */
        sock_release(s);
    } else {
        spin_unlock_bh(&client_lock);
    }
    
    /* Close listening socket */
    if (sock) {
        sock_release(sock);
        sock = NULL;
    }
}

void netlog_printk(const char *fmt, ...)
{
    va_list args;
    char *buf = NULL;
    int len, ret;
    bool client_connected = false;
    
    /* Check if we have a connected client */
    spin_lock_bh(&client_lock);
    client_connected = (client_sock != NULL);
    spin_unlock_bh(&client_lock);
    
    /* If no client connected, don't log anything */
    if (!client_connected) {
        return;
    }
    
    /* Calculate required buffer size */
    va_start(args, fmt);
    len = vsnprintf(NULL, 0, fmt, args) + 1; /* +1 for null terminator */
    va_end(args);
    
    if (len <= 1) {
        printk(KERN_ERR "netlog_printk: Invalid format string\n");
        return;
    }
    
    /* Allocate buffer */
    buf = kmalloc(len, GFP_ATOMIC);  /* Use GFP_ATOMIC as we might be in interrupt context */
    if (!buf) {
        printk_ratelimited(KERN_ERR "netlog_printk: Failed to allocate %d bytes\n", len);
        return;
    }
    
    /* Format the message */
    va_start(args, fmt);
    vsnprintf(buf, len, fmt, args);
    va_end(args);
    
    /* Send the message to connected client */
    ret = netlog_send(buf, strlen(buf));
    if (ret < 0 && ret != -ENOTCONN) {
        printk_ratelimited(KERN_ERR "netlog_printk: Failed to send message: %d\n", ret);
    }
    
    kfree(buf);
}

/**
 * netlog_init_and_wait - Initialize network logger and wait for client
int netlog_init_and_wait(unsigned int timeout_sec)
{
    int err;
    
    /* Initialize network logger */
    err = netlog_init();
    if (err) {
        printk(KERN_ERR "Failed to initialize network logger: %d\n", err);
        return err;
    }
    
    /* Wait for debug client to connect */
    err = netlog_wait_for_client(timeout_sec);
    if (err) {
        printk(KERN_WARNING "Continuing without debug client connection\n");
    }
    
    return 0;
}

MODULE_DESCRIPTION("Gonzo network logger");
