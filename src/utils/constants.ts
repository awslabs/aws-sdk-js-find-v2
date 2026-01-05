export const PACKAGE_JSON = "package.json";

export const NODE_MODULES = "node_modules";

export const AWS_SDK = "aws-sdk";

export interface FileInfo {
  // Path of the file within the zip archive.
  path: string;

  // Contents of the file.
  content: string;
}
