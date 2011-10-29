#ifndef USERFW_RULES_H
#define USERFW_RULES_H

#define	USERFW_RULES_VERSION	20111026

/* Packet direction */
#define USERFW_IN	0
#define USERFW_OUT	1

/* Match types */
#define M_OR	0
#define M_AND	1
#define M_NOT	2
#define M_SRCADDR	3
#define M_DSTADDR	4
#define M_SRCPORT	5
#define M_DSTPORT	6
#define M_UID	7
#define M_IMAGENAME	8
#define M_IMAGEPATH	9
#define M_IMAGEMD5	10

/* Action types */
#define A_ALLOW	0
#define A_DENY	1
#define A_ASK	2

#endif /* USERFW_RULES_H */
