# Copyright 2017 Big Switch Networks, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


class Util(object):
    """
    Placeholder for static methods that can be called from across the plugin
    and reused as required.
    """

    @staticmethod
    def format_resource_name(name):
        """
        Util method to format resource names to make them compatible with BCF.

        Replaces special characters with its corresponding BCF compatible
        encoding.

        :param name non empty string which is the name of the resource
        :rtype string name with special characters replaced
        """
        return (name
                # always replace underscores first, since other replacements
                # contain underscores as part of replacement
                .replace('_', '__')
                .replace(' ', '_s')
                .replace('\'', '_a')
                .replace('/', '_f')
                .replace('[', '_l')
                .replace(']', '_r'))
