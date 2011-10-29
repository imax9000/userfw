#ifndef USERFW_RULES_H
#define USERFW_RULES_H

#define	USERFW_RULES_VERSION	20111026

/* Packet direction */
enum userfw_direction
{
	USERFW_IN = 0
	,USERFW_OUT
};

/* Match types */
enum userfw_match_type
{
	M_ANY = 0
	,M_OR
	,M_AND
	,M_NOT
	,M_SRCIPV4
	,M_DSTIPV4
	,M_SRCPORT
	,M_SRCPORT
	,M_UID
	,M_IMAGENAME
	,M_IMAGEPATH
	,M_IMAGEMD5
};

/* Action types */
enum userfw_action_type
{
	A_ALLOW = 0
	,A_DENY
	,A_ASK
};

#endif /* USERFW_RULES_H */
