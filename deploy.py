import click
import yaml
import boto3
import logging
from botocore.exceptions import ClientError, WaiterError

__env_account_config = {
    "dev": "0"
}

__logger = logging.getLogger()

@click.command()
@click.option('--account')
@click.option('--apitemplate', default="cf-api.yaml")
@click.option('--lambdatemplate', default="cf-lambda.yaml")
@click.option('--apistackname', default="dropbox-pdf-api-dev")
@click.option('--lambdastackname', default="dropbox-pdf-lambda-dev")
@click.option('--env', required=True, type=click.Choice(['dev', 'test', 'prod']))
@click.option('--apibranch')
@click.option('--apibuild', required=True)
@click.option('--dropbox_webhook_secret', required=True)
@click.option('--dropbox_app_token', required=True)
@click.option('--dropbox_input_path', default="/app/input")
@click.option('--debug', is_flag=True, default=False)
def main(account, apitemplate, lambdatemplate, apistackname, lambdastackname, env, apibranch, apibuild,
         dropbox_webhook_secret, dropbox_app_token, dropbox_input_path, debug):
    # configure
    configure_logging(debug)
    account = account or (__env_account_config[env] if env in __env_account_config else None)
    apistackname = name_for_env(apistackname, env)
    lambdastackname = name_for_env(lambdastackname, env)
    cf_client = boto3.client('cloudformation')
    # create or update stack
    api_params = [
        {'ParameterKey': 'account', 'ParameterValue': account},
        {'ParameterKey': 'env', 'ParameterValue': env},
        {'ParameterKey': 'debug', 'ParameterValue': str(debug).lower()}
    ]
    lambda_params = [
        {'ParameterKey': 'account', 'ParameterValue': account},
        {'ParameterKey': 'apibranch', 'ParameterValue': apibranch},
        {'ParameterKey': 'apibuild', 'ParameterValue': apibuild},
        {'ParameterKey': 'dropboxWebhookSecret', 'ParameterValue': dropbox_webhook_secret},
        {'ParameterKey': 'dropboxAppToken', 'ParameterValue': dropbox_app_token},
        {'ParameterKey': 'dropboxInputPath', 'ParameterValue': dropbox_input_path},
        {'ParameterKey': 'debug', 'ParameterValue': str(debug).lower()}
    ]
    api_update_resp = deploy_stack(stack_name=apistackname,
                 params=api_params, debug=debug,
                 cf_client=cf_client, cf_path=apitemplate)
    print(api_update_resp)
    api_id = boto3.client('cloudformation').describe_stack_resource(
        StackName=apistackname,
        LogicalResourceId='restApi'
    )['StackResourceDetail']['PhysicalResourceId']
    lambda_params.append({'ParameterKey': 'api', 'ParameterValue': api_id})
    lambda_update_resp = deploy_stack(stack_name=lambdastackname,
                 params=lambda_params, debug=debug,
                 cf_client=cf_client, cf_path=lambdatemplate)
    print(lambda_update_resp)


def deploy_stack(stack_name,
                 params,
                 cf_client, cf_path,
                 debug=False,
                 is_update=False):
    __logger.info("deploying %s with params %s" %
                  (stack_name, params))
    resp = None
    with open(cf_path, 'r') as f:
        cf_body = f.read()
        if not is_update:
            try:
                resp = cf_client.create_stack(StackName=stack_name,
                                              TemplateBody=cf_body,
                                              Parameters=params,
                                              Capabilities=['CAPABILITY_NAMED_IAM'],
                                              OnFailure='DELETE',
                                              EnableTerminationProtection=False)
                __logger.info(resp)
                cf_waiter = cf_client.get_waiter('stack_create_complete')
                cf_waiter.wait(
                    StackName=stack_name,
                    WaiterConfig={
                        'Delay': 5,
                        'MaxAttempts': 60
                    }
                )
            except ClientError as e:
                if 'AlreadyExistsException' == e.response['Error']['Code']:
                    resp = deploy_stack(stack_name=stack_name,
                                        params=params,
                                        cf_client=cf_client,
                                        cf_path=cf_path,
                                        debug=debug,
                                        is_update=True)
        else:
            try:
                resp = cf_client.update_stack(StackName=stack_name,
                                              TemplateBody=cf_body,
                                              Parameters=params,
                                              Capabilities=['CAPABILITY_NAMED_IAM'])
                __logger.info(resp)
                cf_waiter = cf_client.get_waiter('stack_update_complete')
                cf_waiter.wait(
                    StackName=stack_name,
                    WaiterConfig={
                        'Delay': 5,
                        'MaxAttempts': 60
                    }
                )
            except WaiterError as e:
                __logger.error(e)
            except ClientError as e:
                __logger.error(e)
                if 'No updates' in e.response['Error']['Message']:
                    __logger.info("Stack is already up to date.")
    return resp


def configure_logging(debug=False):
    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)
    __logger.setLevel(logging.DEBUG if debug else logging.INFO)
    boto3.set_stream_logger('botocore', logging.DEBUG if debug else logging.INFO)
    boto3.set_stream_logger('boto3.resources', logging.DEBUG if debug else logging.INFO)


def name_for_env(name, env):
    return name if name[-1 * len(env):] == env else "%s-%s" % (name, env)


if __name__ == '__main__':
    main()
