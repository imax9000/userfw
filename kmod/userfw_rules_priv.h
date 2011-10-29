#ifndef USERFW_RULES_PRIV_H
#define USERFW_RULES_PRIV_H

#include <sys/types.h>


typedef union __userfw_action
{
	uint16_t	type;

	struct
	{
		uint16_t	type;
	} Simple;
} userfw_action;

typedef union __userfw_match
{
	uint16_t	type;

	struct
	{
		uint16_t	type;
		uint16_t	count;
		union __userfw_match	*rules;
	} LogicBlock;

	struct
	{
		uint16_t	type;
		union __userfw_match	*rule;
	} NotBlock;

	struct
	{
		uint16_t	type;
		uint8_t	length;
		uint8_t *addr;
	} MatchAddr;

	struct
	{
		uint16_t	type;
		uint16_t	port;
	} MatchPort;

	struct
	{
		uint16_t	type;
		uint32_t	uid;
	} MatchUid;

	struct
	{
		uint16_t	type;
		char	*str;
	} MatchImage;
} userfw_match;

typedef struct __userfw_rule
{
	uint16_t	number;
	userfw_action	*action;
	userfw_match	*match;
} userfw_rule;


#endif /* USERFW_RULES_PRIV_H */
