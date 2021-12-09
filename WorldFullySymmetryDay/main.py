# -*- coding: utf-8 -*-
# Author: TinyZ
# Filename: symmetry_date.py
# Date  : Nov 2, 2011

import datetime, time


def strToDatetime(datestr, format='%Y%m%d'):
    try:
        return datetime.datetime.strptime(datestr, format)
    except ValueError:
        return False


def symmetry_date(year_start, year_end):
    for i in range(year_start, year_end + 1):
        test = str(i) + str(i)[::-1]
        result = strToDatetime(test)
        if result:
            print(result.date(),"----->",result.strftime('%Y%m%d'))


if __name__ == '__main__':
    symmetry_date(2000, 2099)