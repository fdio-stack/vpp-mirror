/*
 * vpp_commapi.h
 *
 *  Created on: Nov 20, 2016
 *      Author: alagalah
 */

#ifndef URI_VPP_COMMAPI_H_
#define URI_VPP_COMMAPI_H_

int vpp_socket (int family, int type, int protocol);

int vpp_bind (int s, const struct sockaddr *myaddr, socklen_t addrlen);

int vpp_listen (int s, int backlog);

//static int vpp_accept (int s, struct sockaddr *addr, socklen_t * addrlen, int * flags);

int vpp_accept (int s, struct sockaddr *addr, socklen_t * addrlen);



#endif /* URI_VPP_COMMAPI_H_ */
