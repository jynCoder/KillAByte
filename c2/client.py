from flask import Flask , request, jsonify, render_template

def main():
    render_template(ui/login.html)
    #get user name and password for agent
