# https://docs.virustotal.com/reference/domains-object
def get_verdict(verdict):
    # TODO: use the names defined in the configuration file.
    if verdict['malicious'] > 0:
        return f"malicious ({verdict['malicious']})"
    elif verdict['suspicious'] > 0:
        return f"suspicious ({verdict['suspicious']})"
    elif verdict['harmless'] > 0:
        return f"harmless ({verdict['harmless']})"

    return ""

def get_categories(cats):
    cat_list = ""
    for key in cats:
        cat_list = f"{cat_list} {cats[key]} "

    return cat_list

def get_ssl_info(ssl_certificate):
    ssl_records = "subject: "
    try:
        if ssl_certificate['subject'].get('C') is not None:
            ssl_records += f"{ssl_certificate['subject']['C']}"
        if ssl_certificate['subject'].get('CN') is not None:
            ssl_records += f"/{ssl_certificate['subject']['CN']}"
        if ssl_certificate['subject'].get('L') is not None:
            ssl_records += f"/{ssl_certificate['subject']['L']}"
        if ssl_certificate['subject'].get('O') is not None:
            ssl_records += f"/{ssl_certificate['subject']['O']}"

        ssl_records = f"{ssl_records} alternative names:"
        for key in ssl_certificate['extensions']['subject_alternative_name']:
            ssl_records = f"{ssl_records} {key}"
    except:
        pass

    return ssl_records

def get_dns_records(last_dns_records):
    dns_records = ""
    try:
        for record in last_dns_records:
            if record.get('rname') is not None:
                dns_records = f"{dns_records} {record['rname']} "
            if record.get('value') is not None:
                dns_records = f"{dns_records} {record['value']} "
    except:
        pass

    return dns_records

# https://doc.qt.io/qtforpython-5/overviews/richtext-html-subset.html#supported-html-subset
# XXX: this is just a quick way of beautifying the json response. PRs and
# suggestions to improve it are welcome! like displaying a summary of the
# results, a link to the VT web, etc.
def build_html_report(json_obj, report="", spaces=""):
    for i in json_obj:
        if type(json_obj[i]) == dict:
            report = report + spaces + "<ul><strong>" + i + "</strong>\n"
            report = build_html_report(json_obj[i], report, spaces+"")
            report = report + "</ul>\n"
        elif type(json_obj[i]) == str:
            report = report + spaces + "<li><strong>" + i + ":</strong>  " + json_obj[i].replace("\n", "<br>") + "</li>\n"
        elif type(json_obj[i]) == int or type(json_obj[i]) == bool:
            report = report + spaces + "<li><strong>{0}:</strong>  {1}</li>\n".format(i, json_obj[i])
        elif type(json_obj[i]) == list:
            report = report + spaces + "\n<p><strong>" + i + "</strong>: \n"
            li = ""
            for l in json_obj[i]:
                li = "{0}{1},".format(li, l)
            report = report + spaces + li + "</p>\n"
        elif type(i) == str:
            report = report + spaces + "<ul><strong>" + i + "</strong>: "
            if type(json_obj[i]) == list:
                for l in json_obj[i]:
                    report = "<li>{0}{1}</li>\n".format(report, l)
            else:
                report = "<li>{0}{1}</li>\n".format(report, json_obj[i])
            report = report + spaces + "</ul>\n"

    return report


def report_to_html(json_obj, report="", spaces=""):
    # https://www.virustotal.com/gui/domain/malware.wicar.org
    rpt = build_html_report(json_obj, report, spaces)
    # FIXME: lists indentation
    return "<html><style>ul {list-style: none;}</style><body>" + rpt + "</body></html>"

def report_to_ascii(json_obj, report="", space=""):
    for i in json_obj:
        if type(json_obj[i]) == dict:
            report = report + "\n" + space + i + "\n"
            report = report_to_ascii(json_obj[i], report, space+"    ")
        elif type(json_obj[i]) == str:
            report = report + space + i + ":  " + json_obj[i] + "\n"
        elif type(i) == str:
            report = report + space + " - " + i + ":  "
            if type(json_obj[i]) == list:
                for l in json_obj[i]:
                    report = "{0}{1}\n".format(report, l)
            else:
                report = "{0}{1}\n".format(report, json_obj[i])

    return report
