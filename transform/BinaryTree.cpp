//
// Created by Zhenbang Chen on 2020-03-22.
//

#include "BinaryTree.h"

template <typename T> void Node<T>::walk(const Node<T> *tree) {
    if (tree == NULL) return;

    walk(tree -> left);
    std::cout << tree -> data << "\n";
    walk(tree -> right);
}

template <typename T> Node<T> *Node<T>::insertNode(Node<T> *tree, Node<T> *node) {
    if (!tree) {
        tree = node;
        node -> parent = NULL;
    } else {
        Node<T> *parent, *search = tree;
        bool left = false;
        while (search != NULL) {
            parent = search;
            if (node -> data <= search -> data) {
                search = search -> left;
                left = true;
            } else {
                search = search -> right;
                left = false;
            }
        }
        node -> parent = parent;
        if (left) parent -> left = node;
        else parent -> right = node;
    }

    return tree;
}

template <typename T> Node<T> *Node<T>::find(Node<T> *tree, T value) {
    if (!tree || tree -> data == value) return tree;
    if (value < tree -> data) return find(tree -> left, value);
    else return find(tree -> right, value);
}

template <typename T> Node<T> *Node<T>::minimum(Node<T> *tree) {
    if (!tree) return NULL;

    while (tree -> left) {
        tree = tree -> left;
    }

    return tree;
}

template <typename T> Node<T> *Node<T>::maximum(Node<T> *tree) {
    if (!tree) return NULL;

    while (tree -> right) {
        tree = tree -> right;
    }

    return tree;
}

template <typename T> Node<T> *Node<T>::successor(Node<T> *node) {
    if (!node) return NULL;

    if (node -> right) {
        return minimum(node -> right);
    } else {
        // We need to traverse upwards in the tree to find a node where
        // the node is the left child of a parent
        // parent is the successor

        Node<T> *parent = node -> parent;
        while(parent && node != parent -> left) {
            node = parent;
            parent = node -> parent;
        }

        return parent;
    }

}

// make node U's paarent have node v has its child
template <typename T> Node<T> *Node<T>::transplant(Node<T> *tree, Node<T> *u, Node<T> *v) {
    if (!u -> parent) tree = v;
    else if (u -> parent -> left == u) {
        u -> left = v;
    } else if (u -> parent -> right == u) {
        u -> right = v;
    }
    if (v) v -> parent = u -> parent;
    return tree;
}

template <typename T> Node<T> *Node<T>::deleteNode(Node<T> *tree, Node<T> *node) {
    if (!node -> left) {
        tree = transplant(tree, node, node -> right);
    } else if (!node -> right) {
        tree = transplant(tree, node, node -> left);
    } else {
        // Has two children -- successor must be on the right
        Node <int> *successor = minimum(node -> right);
        assert(successor -> left == NULL);
        if (successor != node -> right) {
            tree = transplant(tree, successor, successor -> right);
            successor -> right = node -> right;
            successor -> right -> parent = successor;
        }

        tree = transplant(tree, node, successor);
        successor -> left = node -> left;
        successor -> left -> parent = successor;
    }
    return tree;
}

template<typename T> std::ostream &operator<<(std::ostream &output, Node<T> node);

template<typename T> std::ostream &operator<<(std::ostream &output, Node<T> node) {
    output << "Value: " << node.data;
    if (node.parent) output << " Parent: " << node.parent -> data;
    if (node.left) output << " Left: " << node.left -> data;
    if (node.right) output << " Right: " << node.right -> data;
    output << "\n";
    return output;
}