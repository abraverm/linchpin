#!/usr/bin/env python
import unittest


class FilterModule(object):
    ''' A filter to translate rule_type '''
    def filters(self):
        return {
            'process_output': self.process_output,
            'get_args': self.get_args,
            'update_role': self.update_role,
            'expand_count': self.expand_count,
            'expand_sg': self.expand_sg,
            'expand_server': self.expand_server
        }

    def process_output(self, results, role):
        if role == 'os_server':
            output = { 'ids': [], 'openstack': [], 'servers': [] }
            for result in results:
                output.ids.append(result.id)
                output.openstack.append(result.openstack)
                output.servers.append(result.server)
            return list(output)

    def get_args(self, res):
        ignored_keys = ['role', 'sub_resources', 'args']
        return {k for k in res.keys() if k not in ignored_keys}

    def expand_count(self, resources):
        '''Expanding requested count to actual resources'''
        new_list = [res for res in resources if res.get('count', 1) == 1]
        to_expand = [res for res in resources if res.get('count', 1) > 1]
        for resource in to_expand:
            count = resource.pop('count')
            for num in count:
                new_resource = resource.copy()
                new_resource.name = '{}_{}'.format(resource.name, num)
                new_list.append(new_resource)
        return new_list

    def translate(self, resource, role, target_keys):
        keys = resource.keys() & target_keys
        new_resource = {k: resource[k] for k in keys}
        new_resource.update({'role': role, 'sub_resources': []})

    def filter_by_role(self, resources, role):
        new_list = [res for res in resources if res.role != role]
        to_expand = [res for res in resources if res.role == role]
        return (new_list, to_expand)

    def expand_sg(self, resources):
        '''Expand Linchpin security group declaration to ansible resources'''
        new_list, to_expand = self.filter_by_role(resources, 'os_sg')
        rule_type = {'inbound': 'ingress', 'outbound': 'egress'}
        rule_keys = ('protocol', 'port_range_max', 'port_range_min',
                     'remote_ip_prefix', 'direction')
        sg_keys = ('name', 'description')
        for resource in to_expand:
            new_resource = self.translate(resource, 'os_security_group',
                                          sg_keys)
            for rule in resource.rules:
                rule.update({'direction': rule_type[rule.rule_type]})
                new_rule = self.translate(rule, 'os_security_group_rule',
                                          rule_keys)
                new_resource.sub_resources.append(new_rule)
            new_list.append(new_resource)
        return new_list

    def expand_server(self, resources):
        '''Expand Linchpin server declaration to ansible resources'''
        new_list, to_expand = self.filter_by_role(resources, 'os_server')
        vol_keys = ('name', 'region_name', 'scheduler_hints', 'size')
        attach_keys = ('device')
        for resource in to_expand:
            resource.update({'sub_resources': []})
            for volume in resource.get('additional_volumes', []):
                vol_resource = self.translate(volume, 'os_volume', vol_keys)
                attach_resource = self.translate(volume, 'os_server_volume',
                                                 attach_keys)
                vol_resource.sub_resources.append(attach_resource)
                resource.sub_resources.append(vol_resource)
            new_list.append(resource)
        return new_list

    def update_role(self, deployments):
        for res in deployments:
            potentials = [k for k in res.keys() if isinstance(res[k], dict)]
            roles = ['server', 'security_group', 'security_group_rule',
                     'volume', 'object', 'keypair', 'heat', 'network',
                     'subnet', 'router']
            role = list(set(potentials) & set(roles))
            res['role'] = role
        return deployments


class TestCollectionUtils(unittest.TestCase):
    def test_expand_count(self):
        self.filter = FilterModule()
        self.assertEqual(self.filter.expand_count(1), '')


if __name__ == '__main__':
    unittest.main()
