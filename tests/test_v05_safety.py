# SPDX-License-Identifier: Apache-2.0
"""Design regressions: classify requests without relying on stale approval hashes."""
import pytest

from conftest import codes, doc
from vchlib import safety


def context(b):
    return (doc(b, 'testcase.llm.example.json').data,
            doc(b, 'roe.yaml').data, doc(b, 'tools.yaml').data,
            doc(b, 'seed-manifest.yaml').data)


def request(method, path, op=None, target='tgt-staging-app'):
    return dict(target_id=target, method=method, path=path,
                step_id=None, graphql_operation=op)


@pytest.mark.parametrize('method', ['DELETE', 'PUT', 'PATCH'])
@pytest.mark.parametrize('op', ['query', 'introspection'])
def test_graphql_label_cannot_hide_write(b, method, op):
    tc, roe, tools, manifest = context(b)
    tc['request_allowlist'].append(request(method, '/api/users/real-user', op))
    assert safety.compute_safety_class(tc, roe, tools, manifest)[0] == 'S3'
    assert 'E-TC-MUTATION-SCOPE' in codes(b)


@pytest.mark.parametrize('method', ['GET', 'DELETE'])
def test_created_id_cannot_change_resource(b, method):
    tc, roe, tools, manifest = context(b)
    tc['request_allowlist'].append(request(method, '/api/users/{created:open_session}'))
    assert safety.compute_safety_class(tc, roe, tools, manifest)[0] == 'S3'
    assert 'E-TC-MUTATION-SCOPE' in codes(b)


def test_created_resource_binding_is_required(b):
    tc, roe, tools, manifest = context(b)
    manifest['create_only_endpoints'][0].pop('created_resource', None)
    assert safety.compute_safety_class(tc, roe, tools, manifest)[0] == 'S3'
    assert 'E-SCHEMA' in codes(b)


def test_nested_resource_with_undeclared_parent_variable_is_rejected(b):
    tc, roe, tools, manifest = context(b)
    tc['request_allowlist'][1]['step_id'] = 'send_message'
    tc['request_allowlist'].append(request('DELETE', '/api/chat/sessions/{created:open_session}/messages/{created:send_message}'))
    # Parent resource must explicitly allow the nested path as well.
    manifest['create_only_endpoints'][0]['created_resource']['path_templates'].append(
        '/api/chat/sessions/{created_id}/messages/{message}')
    # Undeclared variables cannot be introduced even for a parent: fail closed.
    assert safety.compute_safety_class(tc, roe, tools, manifest)[0] == 'S3'


@pytest.mark.parametrize('bad', ['/api/users/{unknown}', '/api/chat/sessions/{created_id}/../users', '/api/users/{id}'])
def test_invalid_resource_declaration(b, bad):
    tc, roe, tools, manifest = context(b)
    manifest['create_only_endpoints'][0]['created_resource']['path_templates'] = [bad]
    assert safety.compute_safety_class(tc, roe, tools, manifest)[0] == 'S3'
    assert 'E-SEED-MANIFEST' in codes(b)


def test_valid_created_path_and_graphql_read(b):
    tc, roe, tools, manifest = context(b)
    tc['request_allowlist'].append(request('DELETE', '/api/chat/sessions/{created:open_session}'))
    tc['request_allowlist'].append(request('POST', '/graphql', 'query'))
    assert safety.compute_safety_class(tc, roe, tools, manifest)[0] == 'S1'


def test_created_source_target_and_order(b):
    tc, roe, tools, manifest = context(b)
    tc['request_allowlist'].append(request('DELETE', '/api/chat/sessions/{created:open_session}', target='tgt-staging-api'))
    tc['target_ids'].append('tgt-staging-api')
    assert safety.compute_safety_class(tc, roe, tools, manifest)[0] == 'S3'
    tc['request_allowlist'].pop()
    tc['request_allowlist'].insert(0, request('DELETE', '/api/chat/sessions/{created:open_session}'))
    assert safety.compute_safety_class(tc, roe, tools, manifest)[0] == 'S3'


def test_parent_binding_cannot_be_substituted():
    endpoint = dict(path_template='/sessions/{session}/messages', created_resource=dict(
        type='message', id_pointer='/id', path_templates=['/sessions/{session}/messages/{created_id}']))
    source = dict(path='/sessions/{created:open_session}/messages')
    assert safety.created_path_allowed('/sessions/{created:open_session}/messages/{created:send}', 'send', source, endpoint)
    assert not safety.created_path_allowed('/sessions/another/messages/{created:send}', 'send', source, endpoint)


def test_consistently_signed_wrong_scope_is_rejected(b, keys):
    from conftest import rederive
    tc, _, _, _ = context(b)
    tc['request_allowlist'].append(request('DELETE', '/api/users/{created:open_session}'))
    rederive(b, keys)
    got = codes(b)
    assert 'E-DERIVED' not in got
    assert 'E-TC-MUTATION-SCOPE' in got
