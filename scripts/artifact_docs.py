#!/usr/bin/python3

import argparse
import os
import yaml

parser = argparse.ArgumentParser(description='Generate artifact documentation.')
parser.add_argument('definition_path', metavar='N', type=str, nargs='+',
                    help='directories containing definitions.')


def load_artifacts(paths):
    result = dict()

    for path in paths:
        for root, dirs, files in os.walk(path):
            for name in files:
                if not name.endswith(".yaml"):
                    continue

                with open(os.path.join(root, name)) as fd:
                    raw_data = fd.read()
                    data = yaml.safe_load(raw_data)
                    data['raw'] = raw_data
                    result[data['name']] = data

    return result

if __name__ == "__main__" :
    args = parser.parse_args()

    artifacts = load_artifacts(args.definition_path)

    print ("""This page displays information about the Velociraptor built in
artifacts. There are %s artifacts in total. Use the navigation menu
to the right to quickly skip to the right artifact
definition. Definitions may be expanded to view the VQL source.""" % len(artifacts))

    for name in sorted(artifacts):
        data = artifacts[name]
        id = name.replace(".", "_")

        print ("""
.. |%sDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#%sDetails" role="button"
     aria-expanded="false" aria-controls="%sDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>
""" % (id, id, id))

        heading = name
        print (heading)
        print ('*' * len(heading))
        print ("|%sDetails| " % id + data.get("description"))
        print ("""
.. raw:: html

  <div class="collapse" id="%sDetails">
  <div class="card card-body">
        """ % (id))
        print (".. code-block:: yaml")
        print ()
        for line in data['raw'].splitlines():
            print ("   " + line)
        print ("\n.. raw:: html\n\n   </div></div>\n")
