#pragma once
#include <cstdlib>
#include "types.h"
#include <string.h>
#include <iostream>
#include <vector>

enum class node_type
{
	INT, STR, LIST, DICT
};

struct dict_node
{
	char* key;
	struct node* val;
};

struct node
{
	node_type type;
	u32 size;
	union 
	{
		int val_int;
		char* val_str;
		struct node** val_arr;
		struct dict_node* val_dict;
	}value;
};

void get_dict_node(std::string name, struct node* curr_node, std::vector<struct dict_node*>& vec);




struct node* node_alloc(node_type type);

void node_free(struct node* n);

struct node* decode(char** s);

void parse_string(char** s, struct node* node);

struct node* parse_string_node(char** s);

struct node* parse_int_node(char** s);

struct node* parse_list_node(char** s);

struct node* parse_dict_node(char** s);

void print_node(struct node* n);


