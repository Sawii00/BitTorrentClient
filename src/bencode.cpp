#include "bencode.h"

void get_dict_node(std::string name, struct node* curr_node, std::vector<struct dict_node*>& vec)
{
	if (!curr_node || curr_node->type == node_type::INT || curr_node->type == node_type::STR)
		return;
	if (curr_node->type == node_type::DICT)
	{
		for (int i = 0; i < curr_node->size; ++i)
		{
			if (curr_node->value.val_dict[i].key == name)
			{
				vec.push_back(curr_node->value.val_dict + i);
			}
			else if (curr_node->value.val_dict[i].val->type == node_type::DICT || curr_node->value.val_dict[i].val->type == node_type::LIST)
			{
				get_dict_node(name, curr_node->value.val_dict[i].val, vec);
			}
		}
	}
	else
	{
		for (int i = 0; i < curr_node->size; ++i)
		{
			get_dict_node(name, curr_node->value.val_arr[i], vec);
		}
		
	}
}

struct node* node_alloc(node_type type)
{
	struct node* res = (struct node*)malloc(sizeof(node));
	if (!res)
		exit(-1);
	res->type = type;
	return res;
}

void node_free(struct node* n)
{
	switch (n->type)
	{
	case node_type::INT:
		free(n);
		return;
	case node_type::STR:
		free(n->value.val_str);
		free(n);
		return;
	case node_type::LIST:
		for(u32 i = 0; i < n->size; ++i)
		{
			node_free(*(n->value.val_arr + i));
		}
		free(n->value.val_arr);
		return;
	case node_type::DICT:
		for (u32 i = 0; i < n->size; ++i)
		{
			free((n->value.val_dict + i)->key);
			node_free((n->value.val_dict + i)->val);
		}
		free(n->value.val_dict);
		return;
	}
}

char* parse_string(char** s)
{
	i32 length = strtol(*s, s, 10);
	(*s)++;
	char* node_str = (char*)malloc(length + 1);
	if (!node_str)
		exit(-1);
	node_str[length] = 0;

	memcpy(node_str, *s, length);
	*s += length;

	return node_str;
}

struct node* parse_string_node(char** s) 
{
	struct node* res = node_alloc(node_type::STR);
	char* cpy = *s;
	res->value.val_str = parse_string(s);
	res->size = strtol(cpy, NULL, 10);
	return res;
}

struct node* parse_int_node(char** s) {

	i32 result = strtol(++(*s), s, 10);
	(*s)++;
	struct node* res = node_alloc(node_type::INT);
	res->value.val_int = result;

	return res;
}

struct node* parse_list_node(char** s) {

	struct node* res = node_alloc(node_type::LIST);

	if (!strcmp(*s, "le"))
	{
		res->size = 0;
		res->value.val_arr = nullptr;
		return res;
	}
	(*s)++;

	std::vector<struct node*> container;

	while (**s != 'e')
	{
		container.push_back(decode(s));
	}
	(*s)++;

	struct node** list = (struct node**)malloc(sizeof(struct node*) * container.size());
	if (!list)
		exit(-1);
	memcpy(list, &container[0], sizeof(struct node*) * container.size());

	res->size = container.size();
	res->value.val_arr = list;

	return res;
}

struct node* parse_dict_node(char** s) {

	struct node* res = node_alloc(node_type::DICT);

	if (!strcmp(*s, "de"))
	{
		res->size = 0;
		res->value.val_dict = nullptr;
		return res;
	}
	(*s)++;

	std::vector<struct dict_node> container;

	while (**s != 'e')
	{
		struct dict_node temp;

		temp.key = parse_string(s);
		temp.val = decode(s);

		container.push_back(temp);
	}
	(*s)++;

	struct dict_node* dict = (struct dict_node*)malloc(sizeof(struct dict_node) * container.size());
	if (!dict)
		exit(-1);
	memcpy(dict, &container[0], sizeof(struct dict_node) * container.size());
	res->size = container.size();
	res->value.val_dict = dict;

	return res;
}

struct node* decode(char** s) 
{
	if(*s[0] == 'i')
		return parse_int_node(s);
	else if (*s[0] == 'l')
		return parse_list_node(s);
	else if (*s[0] == 'd')
		return parse_dict_node(s);
	else if (*s[0] >= '0' && *s[0] <= '9')
		return parse_string_node(s);
	else
	{
		std::cout << *s[0] << ": Parsing Error! Cannot state type of contained data\n";
		exit(1);
	}
}

void print_node(struct node* n)
{
	switch (n->type)
	{
	case node_type::STR:
		std::cout << "(STR) " << n->value.val_str << ' ';
		break;
	case node_type::INT:
		std::cout << "(INT) " << n->value.val_int << ' ';
		break;
	case node_type::LIST:
		std::cout << "[ ";
		for (int i = 0; i < n->size; ++i)
		{
			print_node(*(n->value.val_arr + i));
		}
			std::cout << "]";
		break;
	case node_type::DICT:
		std::cout << "{ ";
		for (int i = 0; i < n->size; ++i)
		{
			std::cout << "(" << (n->value.val_dict + i)->key << ": ";
			print_node((n->value.val_dict + i)->val);
			std::cout << ") ";
		}
		std::cout << "}";
		break;
	}
}
