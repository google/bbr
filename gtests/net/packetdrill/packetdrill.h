/*
 * Copyright 2015 Google Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */
/*
 * Author: xiaoj@google.com (Xiao Jia)
 *
 * Interface for packetdrill.
 *
 * To be tested against as a shared object (*.so) file, implement this
 * interface, export a function "packetdrill_interface_init", and
 * initialize the interface struct passed in with your own functions.
 */

#ifndef __PACKETDRILL_H__
#define __PACKETDRILL_H__

#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/epoll.h>
#include <unistd.h>

struct packetdrill_interface {
	void *userdata;
	void (*free)(void *userdata);
	int (*socket)(void *userdata, int domain, int type, int protocol);
	int (*bind)(void *userdata, int sockfd, const struct sockaddr *addr,
		    socklen_t addrlen);
	int (*listen)(void *userdata, int sockfd, int backlog);
	int (*accept)(void *userdata, int sockfd, struct sockaddr *addr,
		      socklen_t *addrlen);
	int (*connect)(void *userdata, int sockfd, const struct sockaddr *addr,
		       socklen_t addrlen);
	ssize_t (*read)(void *userdata, int fd, void *buf, size_t count);
	ssize_t (*readv)(void *userdata, int fd, const struct iovec *iov,
			 int iovcnt);
	ssize_t (*recv)(void *userdata, int sockfd, void *buf, size_t len,
			int flags);
	ssize_t (*recvfrom)(void *userdata, int sockfd, void *buf, size_t len,
			    int flags, struct sockaddr *src_addr,
			    socklen_t *addrlen);
	ssize_t (*recvmsg)(void *userdata, int sockfd, struct msghdr *msg,
			   int flags);
	ssize_t (*write)(void *userdata, int fd, const void *buf, size_t count);
	ssize_t (*writev)(void *userdata, int fd, const struct iovec *iov,
			  int iovcnt);
	ssize_t (*send)(void *userdata, int sockfd, const void *buf, size_t len,
			int flags);
	ssize_t (*sendto)(void *userdata, int sockfd, const void *buf,
			  size_t len, int flags,
			  const struct sockaddr *dest_addr, socklen_t addrlen);
	ssize_t (*sendmsg)(void *userdata, int sockfd, const struct msghdr *msg,
			   int flags);
	int (*fcntl)(void *userdata, int fd, int cmd, ...);
	int (*ioctl)(void *userdata, int fd, unsigned long request, ...);
	int (*close)(void *userdata, int fd);
	int (*shutdown)(void *userdata, int sockfd, int how);
	int (*getsockopt)(void *userdata, int sockfd, int level, int optname,
			  void *optval, socklen_t *optlen);
	int (*setsockopt)(void *userdata, int sockfd, int level, int optname,
			  const void *optval, socklen_t optlen);
	int (*poll)(void *userdata, struct pollfd *fds, nfds_t nfds,
		    int timeout);
	/* Send @count bytes of data starting from @buf to the TCP stack.
	 * Return 0 on success or -1 on error. */
	int (*netdev_send)(void *userdata, const void *buf, size_t count);
	/* Sniff the next packet leaving the TCP stack.
	 * Put packet data in @buf.  @count is passed in as the buffer size.
	 * The actual number of bytes received should be put in @count.
	 * Set @count to 0 if received nothing.
	 * Set @time_usecs to the receive timestamp.
	 * Return 0 on success or -1 on error. */
	int (*netdev_receive)(void *userdata, void *buf, size_t *count,
			      long long *time_usecs);
	int (*usleep)(void *userdata, useconds_t usec);
	int (*gettimeofday)(void *userdata, struct timeval *tv,
			    struct timezone *tz);
	int (*epoll_create)(void *userdata, int size);
	int (*epoll_ctl)(void *userdata, int epfd, int op, int fd,
			 struct epoll_event *event);
	int (*epoll_wait)(void *userdata, int epfd, struct epoll_event *events,
			  int maxevents, int timeout);
	int (*pipe)(void *userdata, int pipefd[2]);
	int (*splice)(void *userdata, int fd_in, loff_t *off_in, int fd_out,
		      loff_t *off_out, size_t len, unsigned int flags);
};

typedef void (*packetdrill_interface_init_t)(const char *flags,
					     struct packetdrill_interface *);

#endif /* __PACKETDRILL_H__ */
