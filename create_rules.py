import requests
import os

PROM_URL = os.getenv('PROM_URL','http://0.0.0.0:9090')
PROM_API_PATH = '/api/v1/query?query=container_last_seen'
PROM_URL = PROM_URL + PROM_API_PATH

def get_clusters():
    cadvisor_response = requests.get(PROM_URL)
    cadvisor_response = cadvisor_response.json()
    ecs_containers = []
    stray_containers = []
    for result in cadvisor_response['data']['result']:
        if 'container_label_com_amazonaws_ecs_container_name' in result['metric']:
            container_details = {}
            container_details['ecs_container_name'] = result['metric']['container_label_com_amazonaws_ecs_container_name']
            if 'container_label_com_amazonaws_ecs_cluster' in result['metric']:
                container_details['ecs_cluster'] = result['metric']['container_label_com_amazonaws_ecs_cluster']
            else:
                print result['metric']['instance'] 
                continue 
            ecs_containers.append(container_details)
        else:
            if 'name' in result['metric']:
                container_details = {}
                container_details['container_name'] = result['metric']['name']
                container_details['container_host'] = result['metric']['instance']
                stray_containers.append(container_details)
    return ecs_containers, stray_containers


def generate_rules():
    ecs_cont, stray_cont = get_clusters()
    os.remove('containers.rules')
    alerts_file = open('containers.rules', 'a')
    for container in ecs_cont:
        alert_name = container['ecs_cluster']+'_'+container['ecs_container_name']
        alert_name = alert_name.replace('-', '_')  # Prometheus doesn't like '-' in alert
        alert = '''
        ALERT %s_alive_check
        IF absent(container_last_seen{container_label_com_amazonaws_ecs_container_name="%s"})
        FOR 5m
        LABELS { severity = "page" }
        ANNOTATIONS {
            summary = "Container {{ $labels.image }} stopped",
            description = "Container %s has been stopped in %s ECS cluster"
        }

        ''' % (alert_name, container['ecs_container_name'], container['ecs_container_name'], container['ecs_cluster'])
        alerts_file.write(alert)
    for container in stray_cont:
        alert_name = container['container_name']
        alert_name = alert_name.replace('-', '_')  # Prometheus doesn't like '-' in alert
        alert = '''
        ALERT %s_alive_check
        IF absent(container_last_seen{name="%s",instance="%s"})
        FOR 5m
        LABELS { severity = "page" }
        ANNOTATIONS {
            summary = "Container {{ $labels.image }} stopped",
            description = "Container %s has been stopped in %s ECS cluster"
        }

        ''' % (alert_name, container['container_name'], container['container_host'],
                container['container_name'], container['container_host'])
        alerts_file.write(alert)

    alerts_file.close()

if __name__ == '__main__':
    generate_rules()
