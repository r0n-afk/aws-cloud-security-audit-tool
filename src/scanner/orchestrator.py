"""Scan orchestrator: creds probe -> Prowler + ScoutSuite (both) -> boto3 fallback."""
import subprocess

from scanner import prowler_engine, scoutsuite_engine, aws_checks


class EngineUnavailableError(Exception):
    pass


class CredentialsError(Exception):
    pass


def run_scan(timeout=1800):
    if not aws_checks.has_credentials():
        raise CredentialsError(
            'No AWS credentials found. Run `aws configure` or set '
            'AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY, then retry.'
        )

    account, arn = aws_checks.identity()

    engines = []
    raw = []
    errors = []

    if prowler_engine.is_available():
        try:
            raw.extend(prowler_engine.run(timeout=timeout))
            engines.append('prowler')
        except subprocess.TimeoutError:
            errors.append('prowler: scan timed out')
        except Exception as exc:
            errors.append(f'prowler: {exc}')

    if scoutsuite_engine.is_available():
        try:
            raw.extend(scoutsuite_engine.run(timeout=timeout))
            engines.append('scoutsuite')
        except Exception as exc:
            errors.append(f'scoutsuite: {exc}')

    if not engines:
        try:
            raw.extend(aws_checks.run_boto3_checks())
            engines.append('boto3')
        except Exception as exc:
            raise EngineUnavailableError(
                'No scanner engine could run. Install Prowler and/or ScoutSuite, '
                f'or verify AWS credentials/boto3 access. Details: {exc}'
            ) from exc

    if not raw:
        raise EngineUnavailableError(
            'Scan engines returned no usable findings. ' + ('; '.join(errors) if errors else '')
        )

    return {
        'findings': raw,
        'engines': engines,
        'raw_count': len(raw),
        'mode': 'aws',
        'aws_account_id': account,
        'aws_arn': arn,
        'errors': errors,
    }
