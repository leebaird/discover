#!/usr/bin/env python

import os
from xml.dom.minidom import parse
import xml.dom.minidom

os.system('clear')

# Open XML document using minidom parser
DOMTree = xml.dom.minidom.parse('movies.xml')
collection = DOMTree.documentElement
if collection.hasAttribute('shelf'):
     print '\n\nRoot element: %s\n' % collection.getAttribute('shelf')

# Get all the movies in the collection
movies = collection.getElementsByTagName('movie')

# Print details of each movie.
for movie in movies:
     print '***** Movie *****'
     if movie.hasAttribute('title'):
          print 'Title: %s' % movie.getAttribute('title')

     type = movie.getElementsByTagName('type')[0]
     print 'Type: %s' % type.childNodes[0].data
     format = movie.getElementsByTagName('format')[0]
     print 'Format: %s' % format.childNodes[0].data
     rating = movie.getElementsByTagName('rating')[0]
     print 'Rating: %s' % rating.childNodes[0].data
     description = movie.getElementsByTagName('description')[0]
     print 'Description: %s' % description.childNodes[0].data

