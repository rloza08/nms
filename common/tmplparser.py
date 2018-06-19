#!/usr/bin/python3

import os
from common.yamlparser import yamlParser
from jinja2 import FileSystemLoader, select_autoescape, Environment
from pprint import pprint


class MainPageGenerator:
    def __init__(self, app=None, tmplName=None, yamlFile=None):
        self.tmplPath = os.getcwd() + '/nmspy_Russel/templates/' + app
        self.tmplName = tmplName
        self.yamlFile = self.tmplPath + '/yaml/' + yamlFile
        self.environ = Environment(
                        loader=FileSystemLoader(self.tmplPath),
                        autoescape=select_autoescape(['html', 'tmpl'])
                       )


    def menuGenerator(self, menuContent=None):
        template = self.environ.get_template(self.tmplName)

        yamlParse = yamlParser(self.yamlFile)
        yamlContents = yamlParse.parseFile()

        leftNavigation = self.leftMenu(yamlContents)
        header_footer, mainContents = self.mainContents(yamlContents,
                                                        menuContent)
        return template.render(navigation=leftNavigation,
                               main=mainContents,
                               header=header_footer,
                               footer=header_footer) 


    def leftMenu(self, yamlContents=None):
        arr = []
        count = 1
        length = len(yamlContents)

        for length_val in range(length):
            for title in yamlContents:
                if count == yamlContents[title]['sequence']:
                    count = count + 1
                    length = length - 1
                    tooltip = yamlContents[title]['tooltip']
                    menu = {'title': title, 'URL': title, 'tooltip': tooltip}
                    arr.append(menu)

        return arr 


    def mainContents(self, yamlContents=None, leftmenuParam=None):
        mainPageContents = {} 
        header_footer = {}

        for leftMenuTitle in yamlContents:
            if leftmenuParam is None:
                leftmenuParam = 'Dashboard'

            if leftMenuTitle == leftmenuParam:
                for value in yamlContents[leftMenuTitle]:
                    if value in ('sequence', 'tooltip'):
                        pass
                    elif value == 'header':
                        header_footer['header'] = yamlContents[leftMenuTitle][value]
                    elif value == 'footer':
                        header_footer['footer'] = yamlContents[leftMenuTitle][value] 
                    else:
                        for key in yamlContents[leftMenuTitle][value]:
                            url = yamlContents[leftMenuTitle][value][key]['URL']
                            descr = yamlContents[leftMenuTitle][value][key]['DESCR']
                            if value in mainPageContents:
                                dic  = {'title': key, 'URL': url, 'DESCR': descr}
                                mainPageContents[value].append(dic) 
                            else:
                                mainPageContents[value] = [{'title': key,
                                                            'URL': url,
                                                            'DESCR': descr}]

        return header_footer, mainPageContents

 
    def submenuGenerator(self, menuParam): 
        template = self.environ.get_template(self.tmplName)

        yamlParse = yamlParser(self.yamlFile)
        yamlContents = yamlParse.parseFile()

        header_footer, contents = self.mainContents(yamlContents,
                                                    menuParam)
        return template.render(main=contents,
                               header=header_footer,
                               footer=header_footer)

