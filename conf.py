# -*- coding: utf-8 -*-

# flake8: noqa

import tinkerer
import tinkerer.paths

# **************************************************************
# TODO: Edit the lines below
# **************************************************************

# Change this to the name of your blog
project = 'Velociraptor'

# Change this to the tagline of your blog
tagline = 'Hunting for evil - what Velociraptors do best!'

# Change this to the description of your blog
description = 'Velociraptor is a Digital Forensic and Incident Response tool.'

# Change this to your name
author = 'Michael Cohen'

# Change this to your copyright string
copyright = '2018 Velocidex Innovations'

# Change this to your blog root URL (required for RSS feed)
website = 'https://docs.velociraptor.velocidex.com/blog/html/'

# **************************************************************
# More tweaks you can do
# **************************************************************

# Add your Disqus shortname to enable comments powered by Disqus
disqus_shortname = 'velocidex-velociraptor'

# Change your favicon (new favicon goes in _static directory)
html_favicon = '_static/favicon.png'

# Pick another Tinkerer theme or use your own
html_theme = 'dark'

# Theme-specific options, see docs
html_theme_options = {}

# Link to RSS service like FeedBurner if any, otherwise feed is
# linked directly
rss_service = None

# Generate full posts for RSS feed even when using "read more"
rss_generate_full_posts = False

# Number of blog posts per page
posts_per_page = 10

# Character use to replace non-alphanumeric characters in slug
slug_word_separator = '_'

# Set to page under /pages (eg. "about" for "pages/about.html")
landing_page = None

# Set to override the default name of the first page ("Home")
first_page_title = None

# **************************************************************
# Edit lines below to further customize Sphinx build
# **************************************************************

# Add other Sphinx extensions here
extensions = ['tinkerer.ext.blog', 'tinkerer.ext.disqus']

# Add other template paths here
templates_path = ['_templates']

# Add other static paths here
html_static_path = ['_static', tinkerer.paths.static]

# Add other theme paths here
html_theme_path = ['_themes', tinkerer.paths.themes]

# Add file patterns to exclude from build
exclude_patterns = ['drafts/*', '_templates/*']

# Add templates to be rendered in sidebar here
html_sidebars = {
    '**': ['recent.html', 'searchbox.html']
}

# Add an index to the HTML documents.
html_use_index = False

# **************************************************************
# Do not modify below lines as the values are required by
# Tinkerer to play nice with Sphinx
# **************************************************************

source_suffix = tinkerer.source_suffix
master_doc = tinkerer.master_doc
version = tinkerer.__version__
release = tinkerer.__version__
html_title = project
html_show_sourcelink = False
html_add_permalinks = ''

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'monokai'
highlight_language = 'sql'

html_logo = "_static/velo.png"
html_css_files = [
    "velo.css",
    "https://cdnjs.cloudflare.com/ajax/libs/fancybox/3.5.1/jquery.fancybox.min.css",
]

html_sidebars = {
    '**': ['fancybox.html', "searchbox.html"],
    'index': ['recent.html', 'searchbox.html'],
}
