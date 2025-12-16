## @aws-sdk/find-v2

CLI to find resources which call AWS using JavaScript SDK v2

## Prerequisites

- Install [Node.js][install-nodejs].
- Set up [SDK authentication with AWS][] with the required permissions for the task.

## Usage

Running `npx @aws-sdk/find-v2` returns help information.

```console
$ npx @aws-sdk/find-v2

Usage: @aws-sdk/find-v2 [options] [command]

CLI to find resources which call AWS using JavaScript SDK v2

Options:
  -v, --version   output the version number
  -h, --help      display help for command

Commands:
  lambda          Scans Lambda Node.js Functions for JavaScript SDK v2.
  help [command]  display help for command
```

### lambda

Run `lambda` command to scan Lambda Node.js Functions for JavaScript SDK v2.

```console
$ npx @aws-sdk/find-v2 lambda

Note about output:
- [Y] means "aws-sdk" is found in Lambda function, and migration is recommended.
- [N] means "aws-sdk" is not found in Lambda function.
- [?] means script was not able to proceed, and it emits reason.

Reading 4 functions from "us-east-2" region.
[N] fn-without-aws-sdk-in-bundle
[Y] fn-with-aws-sdk-in-bundle
[Y] fn-with-aws-sdk-in-package-json-deps
[N] fn-without-aws-sdk-in-package-json-deps

Done.
```

This script requires AWS Managed Policy [AWSLambda_ReadOnlyAccess][].
It lists all Lambda functions, and performs download, unzip and scan for mentions of JS SDK v2.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.

[AWSLambda_ReadOnlyAccess]: https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSLambda_ReadOnlyAccess.html
[install-nodejs]: https://nodejs.dev/learn/how-to-install-nodejs
[SDK authentication with AWS]: https://docs.aws.amazon.com/sdk-for-javascript/v3/developer-guide/getting-your-credentials.html
