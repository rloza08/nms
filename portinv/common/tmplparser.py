#!/usr/bin/python3

import os
from jinja2 import FileSystemLoader, select_autoescape, Environment
from pprint import pprint


class PageGenerator:
    def __init__(self, tmplName=None):
        self.tmplPath = os.getcwd() + '/portinv/templates/'

        if 'nmspy_Russel' not in self.tmplPath:
            self.tmplPath = os.getcwd() + '/nmspy_Russel/portinv/templates'
            
        self.tmplName = tmplName
        self.environ = Environment(
                        loader=FileSystemLoader(self.tmplPath),
                        autoescape=select_autoescape(['html', 'tmpl'])
                       )

    def pageGenerate(self, restmpl=None, values=None, resPage=None, params=None):
        html = '' 
        if resPage is None:
            resPage = ''
 
        if restmpl:
            resTemplate = self.environ.get_template(restmpl)
            html = resTemplate.render(resPage=resPage, params=params)
        else:
            html = resPage

        template = self.environ.get_template(self.tmplName)
        return template.render(values=values, resPage=html, params=params)

    def resPageGenerate(self, restmpl=None, res=None, hd_det=None):
        html = ''
        if restmpl:
            resTemplate = self.environ.get_template(restmpl)
            html = resTemplate.render(res=res, hd_det=hd_det)

        return html

