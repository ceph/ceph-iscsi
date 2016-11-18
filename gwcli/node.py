#!/usr/bin/env python
__author__ = 'pcuzner@redhat.com'

from configshell_fb import ConfigNode


class UIGroup(ConfigNode):

    def __init__(self, name, parent=None, shell=None):
        ConfigNode.__init__(self, name, parent, shell)
        self.http_mode = self.parent.http_mode

    def reset(self):
        children = set(self.children)  # set of child objects
        for child in children:
            self.remove_child(child)


class UINode(UIGroup):

    display_attributes = None

    def __init__(self, name, parent):
        UIGroup.__init__(self, name, parent)
        self.http_mode = self.parent.http_mode

    def ui_command_info(self):

        field_list = self.display_attributes if self.display_attributes else []
        max_field_size = len(max(field_list, key=len))
        for k in field_list:
            attr_label = k.replace('_', ' ').title()

            attr_value = getattr(self, k)

            if isinstance(attr_value, dict):

                if attr_value:
                    print attr_label
                    max_dict_field = len(max(attr_value.keys(), key=len))
                    for dict_key in sorted(attr_value):

                        if isinstance(attr_value[dict_key], dict):
                            inner_dict = attr_value[dict_key]
                            display_value = ", ".join(["=".join([key, str(val)]) for key, val in inner_dict.items()])
                            print "- {} .. {}".format(dict_key, display_value)
                        else:
                            print "- {} .. {}".format(dict_key, attr_value[dict_key])

                    continue
                else:
                    attr_value = 'UNDEFINED'

            if isinstance(attr_value, list):
                attr_value = [str(s) for s in attr_value]

            print "{:<{}} .. {}".format(attr_label, max_field_size, attr_value)



class UIRoot(ConfigNode):
    """
    The gwcli hierarchy root node.
    """

    def __init__(self, shell, as_root=False):
        ConfigNode.__init__(self, '/', shell=shell)
        self.as_root = as_root


