#!/usr/bin/env python

from configshell_fb import ConfigNode
from gwcli.utils import console_message
import logging

__author__ = 'Paul Cuzner'


class UICommon(ConfigNode):

    def __init__(self, name, parent=None, shell=None):
        ConfigNode.__init__(self, name, parent, shell)
        self.logger = logging.getLogger('gwcli')

    def ui_command_goto(self, shortcut='/'):
        '''
        cd to the bookmark at shortcut.

        See 'help bookmarks' for more info on bookmarks.
        '''
        if shortcut in self.shell.prefs['bookmarks']:
            return self.ui_command_cd(self.shell.prefs['bookmarks'][shortcut])
        else:
            pass

    def get_ui_root(self):
        found = False
        obj = self
        while not found:
            if obj.__class__.__name__ == 'ISCSIRoot':
                break
            obj = obj.parent
        return obj


class UIGroup(UICommon):

    def __init__(self, name, parent=None, shell=None):
        UICommon.__init__(self, name, parent, shell)
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
        """
        Show the attributes of the current object.
        """

        text = self.get_info()

        console_message(text)

    def get_info(self):
        """
        extract the relevant display fields from the object and format
        ready for printing
        :return: (str) object meta data based on object's display_attributes
                 list
        """

        display_text = ''

        if not self.display_attributes:
            return "'info' not available for this item"

        field_list = self.display_attributes
        max_field_size = len(max(field_list, key=len))
        for k in field_list:
            attr_label = k.replace('_', ' ').title()

            attr_value = getattr(self, k)

            if isinstance(attr_value, dict):

                if attr_value:
                    display_text += "{}\n".format(attr_label)
                    max_dict_field = len(max(attr_value.keys(), key=len))
                    for dict_key in sorted(attr_value):

                        if isinstance(attr_value[dict_key], dict):
                            inner_dict = attr_value[dict_key]
                            display_value = ", ".join(["=".join(
                                [key, str(val)]) for key, val in inner_dict.items()])
                            display_text += ("- {:<{}} .. {}\n".format(dict_key,
                                                                       max_dict_field,
                                                                       display_value))

                        else:
                            display_text += ("- {} .. {}\n".format(dict_key,
                                                                   attr_value[dict_key]))

                    continue
                else:
                    attr_value = 'UNDEFINED\n'

            if isinstance(attr_value, list):
                item_1 = True
                attr_string = ''
                for item in attr_value:
                    if item_1:
                        attr_string = "{}\n".format(str(item))
                        item_1 = False
                    else:
                        attr_string += "{}{}\n".format(" " * (max_field_size + 4),
                                                       str(item))

                attr_value = attr_string[:-1]

            display_text += ("{:<{}} .. {}\n".format(attr_label,
                                                     max_field_size,
                                                     attr_value))

        return display_text


class UIRoot(UICommon):
    """
    The gwcli hierarchy root node.
    """

    def __init__(self, shell, as_root=False):
        UICommon.__init__(self, '/', shell=shell)
        self.as_root = as_root
