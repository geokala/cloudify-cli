########
# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.


import os
import urllib
import json
import netaddr
import pkgutil
import tarfile
import tempfile
from time import sleep, time
from StringIO import StringIO

import jinja2
import fabric
import fabric.api

from cloudify import ctx
from cloudify.decorators import operation
from cloudify.exceptions import NonRecoverableError
from cloudify_cli import utils


REST_PORT = 80

# internal runtime properties - used by the CLI to store local context
PROVIDER_RUNTIME_PROPERTY = 'provider'
MANAGER_IP_RUNTIME_PROPERTY = 'manager_ip'
MANAGER_USER_RUNTIME_PROPERTY = 'manager_user'
MANAGER_KEY_PATH_RUNTIME_PROPERTY = 'manager_key_path'
DEFAULT_REMOTE_AGENT_KEY_PATH = '~/.ssh/agent_key.pem'

lgr = None


@operation
def creation_validation(cloudify_packages, **kwargs):
    if not isinstance(cloudify_packages, dict):
        raise NonRecoverableError('"cloudify_packages" must be a '
                                  'dictionary property')
    docker_packages = cloudify_packages.get('docker')

    if not docker_packages or not isinstance(docker_packages, dict):
        raise NonRecoverableError(
            '"docker" must be a non-empty dictionary property under '
            '"cloudify_packages"')

    packages_urls = docker_packages.values()
    agent_packages = cloudify_packages.get('agents', {})
    if not isinstance(agent_packages, dict):
        raise NonRecoverableError('"cloudify_packages.agents" must be a '
                                  'dictionary property')

    packages_urls.extend(agent_packages.values())
    for package_url in packages_urls:
        _validate_package_url_accessible(package_url)


def stop_manager_container(docker_path=None, use_sudo=True):
    if not docker_path:
        docker_path = 'docker'
    command = '{0} stop cfy'.format(docker_path)
    if use_sudo:
        command = 'sudo {0}'.format(command)
    _run_command(command)


def stop_docker_service(docker_service_stop_command=None, use_sudo=True):

    if not docker_service_stop_command:
        docker_service_stop_command = 'service docker stop'
    if use_sudo:
        docker_service_stop_command = 'sudo {0}'\
            .format(docker_service_stop_command)

    # this is needed so that docker will stop using the
    # /var/lib/docker directory, which might be mounted on a
    # volume.
    _run_command(docker_service_stop_command)


def _install_docker_if_required(docker_path, use_sudo,
                                docker_service_start_command):
    # CFY-1627 - plugin dependency should be removed.
    from fabric_plugin.tasks import FabricTaskError

    if not docker_path:
        docker_path = 'docker'
    docker_installed = _is_docker_installed(docker_path, use_sudo)
    if not docker_installed:
        try:
            distro_info = get_machine_distro()
        except FabricTaskError as e:
            err = 'failed getting platform distro. error is: {0}'\
                  .format(str(e))
            lgr.error(err)
            raise
        if 'trusty' not in distro_info:
            err = ('bootstrap using the Docker Cloudify image requires either '
                   'running on \'Ubuntu 14.04 trusty\' or having Docker '
                   'pre-installed on the remote machine.')
            lgr.error(err)
            raise NonRecoverableError(err)

        try:
            lgr.info('installing Docker')
            _run_command('curl -sSL https://get.docker.com/ubuntu/ | sudo sh')
        except FabricTaskError:
            err = 'failed installing docker on remote host.'
            lgr.error(err)
            raise
    else:
        lgr.debug('\"docker\" is already installed.')
        try:
            info_command = '{0} info'.format(docker_path)
            if use_sudo:
                info_command = 'sudo {0}'.format(info_command)
            _run_command(info_command)
        except BaseException as e:
            lgr.debug('Failed retrieving docker info: {0}'.format(str(e)))
            lgr.debug('Trying to start docker service')
            if not docker_service_start_command:
                docker_service_start_command = 'service docker start'
            if use_sudo:
                docker_service_start_command = 'sudo {0}'\
                    .format(docker_service_start_command)
            _run_command(docker_service_start_command)

    if use_sudo:
        docker_exec_command = '{0} {1}'.format('sudo', docker_path)
    else:
        docker_exec_command = docker_path
    return docker_exec_command


def bootstrap_docker(cloudify_packages, docker_path=None, use_sudo=True,
                     agent_local_key_path=None, agent_remote_key_path=None,
                     manager_private_ip=None, provider_context=None,
                     docker_service_start_command=None, privileged=False):
    if agent_remote_key_path is None:
        agent_remote_key_path = DEFAULT_REMOTE_AGENT_KEY_PATH

    if 'containers_started' in ctx.instance.runtime_properties:
        try:
            recover_docker(docker_path, use_sudo, docker_service_start_command)
            # the runtime property specifying the manager openstack instance id
            # has changed, so we need to update the manager deployment in the
            # provider context.
            _update_manager_deployment()
        except Exception:
            # recovery failed, however runtime properties may have still
            # changed. update the local manager deployment only
            _update_manager_deployment(local_only=True)
            raise

        return
    # CFY-1627 - plugin dependency should be removed.
    from fabric_plugin.tasks import FabricTaskError
    global lgr
    lgr = ctx.logger

    manager_ip = fabric.api.env.host_string
    lgr.info('initializing manager on the machine at {0}'.format(manager_ip))


    if ctx.operation.retry_number > 0:
        # TODO: This may break because the retry will get the wrong host IP
        # The host IP should probably be pulled from the runtime property if
        # set?
        if MANAGER_IP_RUNTIME_PROPERTY in ctx.instance.runtime_properties.keys():
            manager_ip = ctx.instance.runtime_properties[MANAGER_IP_RUNTIME_PROPERTY]
        return post_bootstrap_actions(manager_ip=manager_ip,
                                      provider_context=provider_context,
                                      agent_remote_key_path=agent_remote_key_path,
                                      wait_for_services_timeout=15)

    docker_exec_command = _install_docker_if_required(
        docker_path,
        use_sudo,
        docker_service_start_command)

    data_container_name = 'data'
    cfy_container_name = 'cfy'
    if _container_exists(docker_exec_command, data_container_name) or \
            _container_exists(docker_exec_command, cfy_container_name):
        err = 'a container instance with name {0}/{1} already exists.'\
              .format(data_container_name, cfy_container_name)
        raise NonRecoverableError(err)

    docker_image_url = cloudify_packages.get('docker', {}).get('docker_url')
    if not docker_image_url:
        raise NonRecoverableError('no docker URL found in packages')
    try:
        lgr.info('importing cloudify-manager docker image from {0}'
                 .format(docker_image_url))
        _run_command('{0} import {1} cloudify'
                     .format(docker_exec_command, docker_image_url))
    except FabricTaskError as e:
        err = 'failed importing cloudify docker image from {0}. reason:{1}' \
              .format(docker_image_url, str(e))
        lgr.error(err)
        raise NonRecoverableError(err)

    cloudify_config = ctx.node.properties['cloudify']
    security_config = cloudify_config.get('security', {})
    security_config_path = _handle_security_configuration(security_config)

    container_mac = '02:47:53:43:46:59'
    if docker_using_ipv6():
        manager_ip = get_docker_ipv6_ip(netaddr.EUI(container_mac))
        # Most uses of IPv6 addresses require that the address is enclosed in
        # square brackets
        manager_ip = '[{ip}]'.format(ip=manager_ip)

    # The command below causes the container to be assigned a MAC address of
    # 02:47:53:43:46:59 - this is locally assigned and will be visible only
    # on devices attached to the docker bridge. The default configuration of
    # the docker bridge only attaches interfaces to it, meaning that this MAC
    # should only possibly be able to have a conflict with other docker MAC
    # addresses. This MAC is not in the docker range of MAC addresses
    # (02:42:ac:11:*:*), so it should be entirely safe to use unless another
    # container exists on the host with a user defined MAC that happens to be
    # set to this MAC address.
    # The MAC address being set allows us to predict the IPv6 address.
    # It shouldn't cause problems for IPv4 so is not made conditional.
    cfy_management_options = ('-t '
                              '--volumes-from data '
                              '--privileged={0} '
                              '-p 80:80 '
                              '-p 5555:5555 '
                              '-p 5672:5672 '
                              '-p 53229:53229 '
                              '-p 8100:8100 '
                              '-p 8101:8101 '
                              '-p 9200:9200 '
                              '-p 8086:8086 '
                              '-e MANAGEMENT_IP={1} '
                              '-e MANAGER_REST_SECURITY_CONFIG_PATH={2} '
                              '--mac-address="{3}" '
                              '--restart=always '
                              '-d '
                              'cloudify '
                              '/sbin/my_init'
                              .format(privileged,
                                      manager_ip,
                                      security_config_path,
                                      container_mac))

    agent_packages = cloudify_packages.get('agents')
    if agent_packages:
        # compose agent installation command.
        data_container_work_dir = '/tmp/work_dir'
        agents_dest_dir = '/opt/manager/resources/packages'
        agent_packages_install_cmd = \
            _get_install_agent_pkgs_cmd(agent_packages,
                                        data_container_work_dir,
                                        agents_dest_dir)
        agent_pkgs_mount_options = '-v {0} -w {1} ' \
                                   .format(agents_dest_dir,
                                           data_container_work_dir)
    else:
        lgr.info('no agent packages were provided')
        agent_packages_install_cmd = 'echo no agent packages provided'
        agent_pkgs_mount_options = ''

    # command to copy host VM home dir files into the data container's home.
    backup_vm_files_cmd, home_dir_mount_path = _get_backup_files_cmd()
    # copy agent to host VM. the data container will mount the host VM's
    # home-dir so that all files will be backed up inside the data container.
    _copy_agent_key(agent_local_key_path, agent_remote_key_path)

    install_plugins_cmd = _handle_plugins_and_create_install_cmd(
        cloudify_config.get('plugins', {}))

    data_container_start_cmd = '{0} && {1} && {2} && echo Data-only container'\
                               .format(agent_packages_install_cmd,
                                       backup_vm_files_cmd,
                                       install_plugins_cmd)
    data_container_options = ('-t '
                              '{0} '
                              '-v ~/:{1} '
                              '-v /root '
                              '--privileged={2} '
                              '-v /etc/init.d '
                              '-v /etc/default '
                              '-v /opt/manager/resources '
                              '-v /opt/manager/env '
                              '-v /etc/service/riemann '
                              '-v /etc/service/elasticsearch/data '
                              '-v /etc/service/elasticsearch/logs '
                              '-v /opt/influxdb/shared/data '
                              '-v /var/log/cloudify '
                              'cloudify sh -c \'{3}\''
                              .format(agent_pkgs_mount_options,
                                      home_dir_mount_path,
                                      privileged,
                                      data_container_start_cmd))

    try:
        lgr.info('starting a new cloudify data container')
        _run_docker_container(docker_exec_command, data_container_options,
                              data_container_name)
        lgr.info('starting a new cloudify mgmt docker services container')
        _run_docker_container(docker_exec_command, cfy_management_options,
                              cfy_container_name, attempts_on_corrupt=5)
    except FabricTaskError as e:
        err = 'failed running cloudify docker container. ' \
              'error is {0}'.format(str(e))
        lgr.error(err)
        raise NonRecoverableError(err)

    return post_bootstrap_actions(manager_ip=manager_ip,
                                  provider_context=provider_context,
                                  agent_remote_key_path=agent_remote_key_path)


def post_bootstrap_actions(manager_ip,
                           agent_remote_key_path,
                           provider_context,
                           wait_for_services_timeout=180):
    lgr.info('waiting for cloudify management services to start')

    started = _wait_for_management(manager_ip,
                                   timeout=wait_for_services_timeout)

    if not started:
        err = 'failed waiting for cloudify management services to start.'
        lgr.info(err)
        raise NonRecoverableError(err)

    _set_manager_endpoint_data(manager_ip)
    ctx.instance.runtime_properties['containers_started'] = 'True'
    try:
        _upload_provider_context(agent_remote_key_path, provider_context)
    except:
        del ctx.instance.runtime_properties['containers_started']
        raise
    return True


def get_docker_process_command():
    # If this fails, docker isn't running.
    # If docker isn't running by the time we reach the point where this is
    # used then something very interesting went wrong earlier in the bootstrap
    # process.
    docker_processes = _run_command("ps -C docker -o cmd")
    docker_processes = docker_processes.split('\n')

    for line in docker_processes:
        components = line.split()
        if '-d' in components:
            return line


def docker_using_ipv6():
    docker_command = get_docker_process_command()

    if '--ipv6' in docker_command:
        return True
    else:
        return False


def get_docker_ipv6_net():
    docker_command = get_docker_process_command()

    ipv6_net = None

    components = docker_command.split()
    for component in components:
        if component.startswith('--fixed-cidr-v6='):
            ipv6_net = component.split('=')[1].strip("'\"")
    return ipv6_net


def get_docker_ipv6_ip(container_mac):
    container_mac = netaddr.EUI(container_mac)
    docker_net = get_docker_ipv6_net()

    if docker_net is None:
        return calculate_ipv6_link_local(container_mac)
    else:
        # Get the network range docker is using
        ipv6_net = netaddr.IPNetwork(get_docker_ipv6_net())
        # Get the IP address on the docker network based on the MAC address
        return str(ipv6_net[int(container_mac)])


def calculate_ipv6_link_local(container_mac):
    mac = list(container_mac)

    # Insert 0xfffe into the middle of the MAC
    mac.insert(3, 0xfe)
    mac.insert(3, 0xff)

    # Flip bit 6 of the first octet
    mac[0] = mac[0] ^ 2

    # Convert to a string (as that's what we need to return) and prepend the
    # link local prefix 0xfe80
    mac = [hex(octet)[2:] for octet in mac]
    return 'fe80::{0}{1}:{2}{3}:{4}{5}:{6}{7}'.format(*mac)


def recover_docker(docker_path=None, use_sudo=True,
                   docker_service_start_command=None):
    global lgr
    lgr = ctx.logger

    manager_ip = fabric.api.env.host_string
    lgr.info('initializing manager on the machine at {0}'.format(manager_ip))
    _install_docker_if_required(docker_path, use_sudo,
                                docker_service_start_command)

    lgr.info('waiting for cloudify management services to restart')
    started = _wait_for_management(manager_ip, timeout=180)
    _recover_deployments(docker_path, use_sudo)
    if not started:
        err = 'failed waiting for cloudify management services to restart.'
        lgr.info(err)
        raise NonRecoverableError(err)


def _recover_deployments(docker_path=None, use_sudo=True):

    ctx.logger.info('Recovering deployments...')
    script_relpath = ctx.instance.runtime_properties.get(
        'recovery_script_relpath')
    if not script_relpath:
        raise NonRecoverableError('Cannot recover deployments. No recovery '
                                  'script specified.')
    script = ctx.download_resource(
        script_relpath)
    fabric.api.put(script, '~/recover_deployments.sh')
    _run_command('chmod +x ~/recover_deployments.sh')
    _run_command_in_cfy('/tmp/home/recover_deployments.sh',
                        docker_path=docker_path,
                        use_sudo=use_sudo)


def _get_backup_files_cmd():
    container_tmp_homedir_path = '/tmp/home'
    backup_homedir_cmd = 'cp -rf {0}/. /root' \
                         .format(container_tmp_homedir_path)
    return backup_homedir_cmd, container_tmp_homedir_path


def _get_install_agent_pkgs_cmd(agent_packages,
                                agents_pkg_path,
                                agents_dest_dir):
    download_agents_cmd = ''
    install_agents_cmd = ''
    for agent_name, agent_url in agent_packages.items():
        # Connect timeout and retry handle IPv6 in docker and temporary issues
        # with networks. '-g' disables globbing, which is required when IPv6
        # addresses are supplied.
        download_agents_cmd += ('curl --connect-timeout 3 '
                                '--retry 3 -g -O "{0}" {1} ').format(agent_url,
                                                                     '&&')

    install_agents_cmd += 'rm -rf {0}/* && dpkg -i {1}/*.deb' \
                          .format(agents_dest_dir,
                                  agents_pkg_path)

    return '{0} {1}'.format(download_agents_cmd, install_agents_cmd)


def _handle_plugins_and_create_install_cmd(plugins):
    # no plugins configured, run a stub 'true' command
    if not plugins:
        return 'true'

    cloudify_plugins = 'cloudify/plugins'
    install_plugins = 'install_plugins.sh'

    # create location to place tar-gzipped plugins in
    _run_command('mkdir -p ~/{0}'.format(cloudify_plugins))

    # for each plugin tha is included in the blueprint, tar-gzip it
    # and place it in the plugins dir on the host
    for name, plugin in plugins.items():
        source = plugin['source']
        if source.split('://')[0] in ['http', 'https']:
            continue

        # temporary workaround to resolve absolute file path
        # to installed plugin using internal local workflows storage
        # information
        plugin_path = os.path.join(ctx._endpoint.storage.resources_root,
                                   source)

        with tempfile.TemporaryFile() as fileobj:
            with tarfile.open(fileobj=fileobj, mode='w:gz') as tar:
                tar.add(plugin_path, arcname=name)
            fileobj.seek(0)
            tar_remote_path = '{0}/{1}.tar.gz'.format(cloudify_plugins, name)
            fabric.api.put(fileobj, '~/{0}'.format(tar_remote_path))
            plugin['source'] = 'file:///root/{0}'.format(tar_remote_path)

    # render script template and copy it to host's home dir
    script_template = pkgutil.get_data('cloudify_cli.bootstrap.resources',
                                       'install_plugins.sh.template')
    script = jinja2.Template(script_template).render(plugins=plugins)
    fabric.api.put(StringIO(script), '~/{0}'.format(install_plugins))
    _run_command('chmod +x ~/{0}'.format(install_plugins))
    # path to script on container after host's home has been copied to
    # container's home
    return '/root/{0}'.format(install_plugins)


def _is_docker_installed(docker_path, use_sudo):
    """
    Returns true if docker run command exists
    :param docker_path: the docker path
    :param use_sudo: use sudo to run docker
    :return: True if docker run command exists, False otherwise
    """
    # CFY-1627 - plugin dependency should be removed.
    from fabric_plugin.tasks import FabricTaskError
    try:
        if use_sudo:
            out = fabric.api.run('sudo which {0}'.format(docker_path))
        else:
            out = fabric.api.run('which {0}'.format(docker_path))
        if not out:
            return False
        return True
    except FabricTaskError:
        return False


def _wait_for_management(ip, timeout, port=REST_PORT):
    """ Wait for url to become available
        :param ip: the manager IP
        :param timeout: in seconds
        :param port: port used by the rest service.
        :return: True of False
    """
    validation_url = 'http://{0}:{1}/version'.format(ip, port)

    end = time() + timeout

    while end - time() >= 0:
        try:
            status = urllib.urlopen(validation_url).getcode()
            if status == 200:
                return True

        except IOError as e:
            lgr.debug('error waiting for {0}. reason: {1}'
                      .format(validation_url, e.message))
        sleep(5)

    return False


def _set_manager_endpoint_data(manager_ip):
    ctx.instance.runtime_properties[MANAGER_IP_RUNTIME_PROPERTY] = \
        manager_ip
    ctx.instance.runtime_properties[MANAGER_USER_RUNTIME_PROPERTY] = \
        fabric.api.env.user
    ctx.instance.runtime_properties[MANAGER_KEY_PATH_RUNTIME_PROPERTY] = \
        fabric.api.env.key_filename


def _handle_security_configuration(blueprint_security_config):
    remote_security_config_path = '~/rest-security-config.json'
    container_security_config_path = '/root/rest-security-config.json'
    secured_server = blueprint_security_config.get('enabled', False)
    securest_userstore_driver = blueprint_security_config.get(
        'userstore_driver', {})
    securest_authentication_providers = blueprint_security_config.get(
        'authentication_providers', [])
    auth_token_generator = blueprint_security_config.get(
        'auth_token_generator', {})
    # TODO: this is the place to provide initial validation for the security
    # related configuration parts.
    security_config = dict(
        secured_server=secured_server,
        securest_userstore_driver=securest_userstore_driver,
        securest_authentication_providers=securest_authentication_providers,
        auth_token_generator=auth_token_generator)
    security_config_file_obj = StringIO()
    json.dump(security_config, security_config_file_obj)
    fabric.api.put(security_config_file_obj, remote_security_config_path)
    return container_security_config_path


def _copy_agent_key(agent_local_key_path, agent_remote_key_path):
    if not agent_local_key_path:
        return
    agent_local_key_path = os.path.expanduser(agent_local_key_path)
    ctx.logger.info(
        'Copying agent key to management machine: {0} -> {1}'.format(
            agent_local_key_path, agent_remote_key_path))
    fabric.api.put(agent_local_key_path, agent_remote_key_path)


def _update_manager_deployment(local_only=False):

    # get the current provider from the runtime property set on bootstrap
    provider_context = ctx.instance.runtime_properties[
        PROVIDER_RUNTIME_PROPERTY]

    # construct new manager deployment
    provider_context['cloudify'][
        'manager_deployment'] = _dump_manager_deployment()

    # update locally
    ctx.instance.runtime_properties[
        PROVIDER_RUNTIME_PROPERTY] = provider_context
    with utils.update_wd_settings() as wd_settings:
        wd_settings.set_provider_context(provider_context)

    if not local_only:
        # update on server
        rest_client = utils.get_rest_client()
        rest_client.manager.update_context('provider', provider_context)


def get_container_ipv6_address():
    # Should get sudo setting, but working in same fashion as
    # _upload_provider_context at the moment and assuming it
    container_details = json.loads(_run_command('sudo docker inspect cfy'))
    container_networking = container_details[0]['NetworkSettings']

    ipv6 = None

    if 'GlobalIPv6Address' in container_networking.keys():
        ipv6 = container_networking['GlobalIPv6Address']

    return ipv6


def _upload_provider_context(remote_agents_private_key_path,
                             provider_context=None):
    ctx.logger.info('updating provider context on management server...')
    provider_context = provider_context or dict()
    cloudify_configuration = ctx.node.properties['cloudify']
    cloudify_configuration['cloudify_agent']['agent_key_path'] = \
        remote_agents_private_key_path
    provider_context['cloudify'] = cloudify_configuration
    ctx.instance.runtime_properties[PROVIDER_RUNTIME_PROPERTY] = \
        provider_context

    # 'manager_deployment' is used when running 'cfy use ...'
    # and then calling teardown or recover. Anyway, this code will only live
    # until we implement the fuller feature of uploading manager blueprint
    # deployments to the manager.
    cloudify_configuration['manager_deployment'] = _dump_manager_deployment()

    remote_provider_context_file = '~/provider-context.json'
    container_provider_context_file = '/tmp/home/provider-context.json'
    provider_context_json_file = StringIO()
    full_provider_context = {
        'name': 'provider',
        'context': provider_context
    }
    json.dump(full_provider_context, provider_context_json_file)

    # placing provider context file in the manager's host
    fabric.api.put(provider_context_json_file,
                   remote_provider_context_file)

    manager_ip = ctx.instance.runtime_properties[MANAGER_IP_RUNTIME_PROPERTY]

    upload_provider_context_cmd = \
        'curl -g --fail -XPOST \'{ip}\':8101/provider/context -H ' \
        '"Content-Type: application/json" -d @{context}'.format(
            ip=manager_ip,
            context=container_provider_context_file)

    # uploading the provider context to the REST service
    _run_command_in_cfy(upload_provider_context_cmd, terminal=True)


def _run_command(command, shell_escape=None):
    return fabric.api.run(command, shell_escape=shell_escape)


def _run_command_in_cfy(command, docker_path=None, use_sudo=True,
                        terminal=False):
    if not docker_path:
        docker_path = 'docker'
    exec_command = 'exec -t' if terminal else 'exec'
    full_command = '{0} {1} cfy {2}'.format(
        docker_path, exec_command, command)
    if use_sudo:
        full_command = 'sudo {0}'.format(full_command)
    _run_command(full_command)


def _container_exists(docker_exec_command, container_name):
    # CFY-1627 - plugin dependency should be removed.
    from fabric_plugin.tasks import FabricTaskError
    try:
        inspect_command = '{0} inspect {1}'.format(docker_exec_command,
                                                   container_name)
        _run_command(inspect_command)
        return True
    except FabricTaskError:
        return False


def _run_docker_container(docker_exec_command, container_options,
                          container_name, attempts_on_corrupt=1):
    # CFY-1627 - plugin dependency should be removed.
    from fabric_plugin.tasks import FabricTaskError
    run_cmd = '{0} run --name {1} {2}'\
              .format(docker_exec_command, container_name, container_options)
    for i in range(0, attempts_on_corrupt):
        try:
            lgr.debug('starting docker container {0}'.format(container_name))
            return _run_command(run_cmd)
        except FabricTaskError:
            lgr.debug('container execution failed on attempt {0}/{1}'
                      .format(i + 1, attempts_on_corrupt))
            container_exists = _container_exists(docker_exec_command,
                                                 container_name)
            if container_exists:
                lgr.debug('container {0} started in a corrupt state. '
                          'removing container.'.format(container_name))
                rm_container_cmd = '{0} rm -f {1}'.format(docker_exec_command,
                                                          container_name)
                _run_command(rm_container_cmd)
            if not container_exists or i + 1 == attempts_on_corrupt:
                lgr.error('failed executing command: {0}'.format(run_cmd))
                raise
            sleep(2)


def get_machine_distro():
    return _run_command('python -c "import platform, json, sys; '
                        'sys.stdout.write(\'{0}\\n\''
                        '.format(json.dumps(platform.dist())))"')


def _validate_package_url_accessible(package_url):
    ctx.logger.debug('checking whether url {0} is accessible'.format(
        package_url))
    status = urllib.urlopen(package_url).getcode()
    if not status == 200:
        err = ('url {0} is not accessible'.format(package_url))
        ctx.logger.error('VALIDATION ERROR: ' + err)
        raise NonRecoverableError(err)
    ctx.logger.debug('OK: url {0} is accessible'.format(package_url))


# temp workaround to enable teardown and recovery from different machines
def _dump_manager_deployment():
    from cloudify_cli.bootstrap.bootstrap import dump_manager_deployment
    from cloudify_cli.bootstrap.bootstrap import load_env

    # explicitly write the manager node instance id to local storage
    env = load_env('manager')
    with env.storage.payload() as payload:
        payload['manager_node_instance_id'] = ctx.instance.id

    # explicitly flush runtime properties to local storage
    ctx.instance.update()
    return dump_manager_deployment()
