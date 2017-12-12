#!/usr/bin/env python
# -*- coding: utf-8 -*-

# @Time    : 2017/9/20 12:00
# @Author  : Shawn
# @File    : dnspod.py
# @Software: PyCharm

import ConfigParser
import json
import urllib2
import urllib
import time
import os
import sys

reload(sys)
sys.setdefaultencoding('utf-8')

# 读取配置文件
cf = ConfigParser.ConfigParser()
cf.read("config.ini")

dns_id = cf.get("dnspodcfg", "dns_id")
token = cf.get("dnspodcfg", "dns_token")


__POST_DOMAIN = 'https://dnsapi.cn'
__HEADERS = {'UserAgent': 'IDS dnsAPI 1.0 (shawn.pan@idreamsky.com)'}


# 获取时间字符串
def get_time():
    return '[' + time.strftime('%Y-%m-%d %X', time.localtime()) + '] '


# 记录日志
def logger(log_type, log_str):
    try:
        f = open('log/' + time.strftime('%Y%m%d', time.localtime()) + '.log', 'a')
        logger_str = get_time() + '[' + log_type + '] ' + log_str + '\n'
        f.write(logger_str)
        print logger_str,
    except IOError, e:
        print e
    finally:
        f.closed
    return


# 输入域名记录字典，备份到本地文件
def backup_local_file(record_dic):
    for domains, domain_values in record_dic.items():
        backup_path = 'backup/' + time.strftime('%Y%m%d', time.localtime())
        try:
            if not os.path.isdir(backup_path):
                os.mkdir(backup_path)
            f = open(backup_path + '/' + time.strftime('%H%M%S', time.localtime()) + '-' + str(domains) + ".txt", 'w')
            for domain_value in domain_values:
                f.writelines(str(domain_value) + '\n')
        except Exception, e:
            logger('ERROR', str(e))
            print e,
        finally:
            f.closed

        logger('INFO', 'Backup domain: ' + domains + ' records to local success')

    return
"""
format 
{u'status': u'enabled', 
u'monitor_status': u'', 
u'remark': u'\u6551\u4e16\u4e3b\u8054\u76df\u5b98\u7f51\u57df\u540d\uff0cadd by kevin 20150704,fisher.qin\u7533\u8bf7', 
u'name': u'www', 
u'weight': None, 
u'mx': u'0', 
u'enabled': u'0', 
u'value': u'bj1.1uwan.com.', 
u'use_aqb': u'no', 
u'line_id': u'0', 
u'ttl': u'600', 
u'updated_on': u'2015-09-02 13:55:34', 
u'line': u'\u9ed8\u8ba4', 
u'type': u'CNAME', 
u'id': u'110591328'}
"""


# 输入域名记录字典，备份到mysql数据库
def backup_mysql(record_dic):
    return logger('WARNING' + 'not yet support ' + record_dic)


def get_data_from_dns(post_url, post_data):
    req = urllib2.Request(url=post_url, data=urllib.urlencode(post_data), headers=__HEADERS)
    rst_tmp = urllib2.urlopen(req)
    rst_tmp.encoding = 'utf-8'
    rst = rst_tmp.read()
    return_data = json.loads(rst)
    return return_data


# 获取域名列表
def get_domain_list():
    domain_list = []
    post_url = __POST_DOMAIN + '/Domain.List'
    post_data = {
        'lang': "cn",
        'login_token': dns_id + ',' + token,
        'format': "json",
    }

    deal_json = get_data_from_dns(post_url, post_data)
    if deal_json["status"]["code"] == '1':
        logger('INFO', 'Get domain list success')
        for items in deal_json["domains"]:
            domain_list.append(items["name"])
    else:
        logger('ERROR', 'Get domain list failed')
        print "bad getDomainList",
    return domain_list


# 输入域名，获取记录列表
def get_record_list(domain):
    post_url = __POST_DOMAIN + '/Record.List'
    post_data = {
        'lang': "cn",
        'login_token': dns_id + ',' + token,
        'format': "json",
        'domain': domain,
    }
    deal_json = get_data_from_dns(post_url, post_data)
    if deal_json["status"]["code"] == '1':
        logger('INFO', 'Get domain: ' + domain + ' record list success')
        list_domain_record = []
        if (int(deal_json["info"]["record_total"])) <= 3000:
            for record in deal_json["records"]:
                list_domain_record.append(record)
        else:
            logger('WARNING', 'Get domain: ' + domain + ' record list failed, only support less than 3000')
            # print "record max is 3000",
        return list_domain_record
    else:
        logger('ERROR', 'Get domain: ' + domain + ' record list failed ' + deal_json["status"]["message"])
        # print "bad backupDomains"
        return


# 输入域名列表，输出记录字典
def get_record_dic(domain_list):
    record_dic = {}
    for domain in domain_list:
        record_dic[domain] = get_record_list(domain)
    return record_dic


# 备份全部域名记录
def backup_all():
    backup_local_file(get_record_dic(get_domain_list()))


# 输入域名和子域名，判断子域名是否存在
def get_record_id(domain_name, domain_sub_name):
    list_domain = get_record_list(domain_name)
    if len(list_domain) == 0:
        logger('WARNING', 'Domain:' + domain_name + ' does not have record')
        return -1
    else:
        for dic_rec in list_domain:
            if domain_sub_name == str(dic_rec['name']):
                logger('INFO', 'Domain:' + domain_sub_name + '.' + domain_name + ' get record')
                return int(dic_rec['id'])
        logger('WARNING', 'Domain:' + domain_sub_name + '.' + domain_name + ' no record')
        return -2


def is_record(domain_name, domain_sub_name):
    return True if get_record_id(domain_name, domain_sub_name) > 0 else False


def add_record(domain_name, domain_sub_name, record_type, value):
    rec_id = get_record_id(domain_name, domain_sub_name)
    if rec_id < 0:
        post_url = __POST_DOMAIN + '/Record.Create'
        post_data = {
            'lang': "cn",
            'login_token': dns_id + ',' + token,
            'format': "json",
            # 'domain': domain_name,
            'record_line': '默认',
            'record_type': record_type,
            'sub_domain': domain_sub_name,
            'value': value,
        }
        deal_json = get_data_from_dns(post_url, post_data)
        # print deal_json
        if (deal_json['status']['code']) == '1':
            logger('INFO', 'success add domain:' + domain_sub_name + '.' + domain_name)
            return deal_json['record']['id']
        else:
            logger('ERROR', 'failed add domain:' + str(domain_sub_name.encode('utf-8')) + '.' +
                   str(domain_name.encode('utf-8')) + '. ' + deal_json['status']['message'])
            return -2
    else:
        logger('ERROR', 'record exists')
        return -1


def add_record_detail(domain_name, domain_sub_name, record_type, value, remark):
    rec_id = get_record_id(domain_name, domain_sub_name)
    if rec_id < 0:
        post_url = __POST_DOMAIN + '/Record.Create'
        post_data = {
            'lang': "cn",
            'login_token': dns_id + ',' + token,
            'format': "json",
            'record_line': '默认',
            'record_type': record_type,
            'domain': domain_name,
            'sub_domain': domain_sub_name,
            'value': value,
        }

        deal_json = get_data_from_dns(post_url, post_data)
        if (deal_json['status']['code']) == '1':
            logger('INFO', 'success add domain:' + domain_sub_name + '.' + domain_name)
            try:
                mark_record(domain_name, deal_json['record']['id'], remark)
            except Exception, e:
                logger('WARNING', 'add domain ' + domain_sub_name + '.' + domain_name + ' remark failed')
                print e
            return deal_json['record']['id']
        else:
            logger('ERROR', 'failed add domain:' + str(domain_sub_name.encode('utf-8')) + '.' +
                   str(domain_name.encode('utf-8')) + '. ' + deal_json['status']['message'])
            return -2
    else:
        logger('ERROR', 'record exists')
        return -1


def mark_record(domain_name, record_id, remark):
    post_url = __POST_DOMAIN + '/Record.Remark'
    post_data = {
        'lang': "cn",
        'login_token': dns_id + ',' + token,
        'format': "json",
        'domain': domain_name,
        'record_id': record_id,
        'remark': remark,
    }
    deal_json = get_data_from_dns(post_url, post_data)
    if deal_json['status']['code'] == '1':
        logger('INFO', 'remark ' + domain_name + ' ' + record_id + ' success')
    else:
        logger('ERROR', 'remark ' + domain_name + ' ' + record_id + 'failed.' + deal_json['status']['message'])


def del_record(domain_name, domain_sub_name):
    rec_id = get_record_id(domain_name, domain_sub_name)
    if rec_id > 0:
        post_url = __POST_DOMAIN + '/Record.Remove'
        post_data = {
            'lang': "cn",
            'login_token': dns_id + ',' + token,
            'format': "json",
            'record_line': '默认',
            'domain': domain_name,
            'sub_domain': domain_sub_name,
            'record_id': rec_id,
        }
        deal_json = get_data_from_dns(post_url, post_data)
        if (deal_json['status']['code']) == '1':
            logger('INFO', 'success delete domain:' + domain_sub_name + '.' + domain_name + ' record')
            return True
        else:
            logger('ERROR', 'failed delete domain:' + str(domain_sub_name.encode('utf-8')) +
                   '.' + str(domain_name.encode('utf-8')) + '. ' + deal_json['status']['message'])
            return False
    else:
        logger('ERROR', 'record does not exists, cannot delete')
        return False


def add_rec(add_domain_file):
    try:
        f = open(add_domain_file, 'r')
        with f as file:
            for line in f:
                line_list = line.split()

                if len(line_list) is not 6:
                    logger('ERROR', 'Add record failed. domain:' + line_list + ' ' + ' '.join(line_list))
                    continue

                # test1.pandachun.com 218.18.232.223 shawn shing A 圣斗士测试
                rec_dom = line_list[0]
                split_domain = rec_dom.split('.')
                domain_name = '.'.join(split_domain[-2:])
                domain_sub_name = '.'.join(split_domain[0:(len(split_domain)-2)])
                ip = str(line_list[1])
                add_user = line_list[2]
                req_user = line_list[3]
                rec_type = line_list[4]
                project = line_list[5]
                op_date = time.strftime('%Y%m%d', time.localtime())

                remark = 'add for ' + project + ',create by ' + add_user + ' ' + op_date + ', ' + req_user + ' 申请'\
                         + ' AUTO'

                add_record_detail(domain_name, domain_sub_name, rec_type, ip, remark)

    except Exception, e:
        logger('ERROR', 'catch add_rec exception ' + e)
    finally:
        f.closed
    return


def del_rec(del_domain_file):
    try:
        f = open(del_domain_file,'r')
        with f as file:
            for line in f:
                line_list = line.split()

                rec_dom = line_list[0]
                split_domain = rec_dom.split('.')
                domain_name = '.'.join(split_domain[-2:])
                domain_sub_name = '.'.join(split_domain[0:(len(split_domain)-2)])
                del_record(domain_name, domain_sub_name)
    except Exception, e:
        logger('ERROR', 'catch del_rec exception ' + str(e))
    finally:
        f.closed
    return

backup_all()
add_rec('add_record.conf')
# del_rec('del_record.conf')
