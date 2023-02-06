from jinja2 import Environment,FileSystemLoader
import os
import time

def generate_html(items, template_name, vulType):
    env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__),'../../templates/')))
    # template = env.get_template('template_ssrf.html')
    template = env.get_template(template_name)
    report_dir = os.path.join(os.path.dirname(__file__),'../../reports/')
    t = time.strftime("%Y-%m-%d")
    # report_filename = report_dir + 'SSRF-'+ t + '.html'
    report_filename = report_dir + vulType + '-'+ t + '.html'
    with open(report_filename, 'w', encoding='utf-8') as fp:
        html_content = template.render(items=items)
        fp.write(html_content)

# if __name__ == '__main__':
#     generate_html({})


