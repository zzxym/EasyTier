declare module '*.yaml' {
  const value: Record<string, string>;
  export default value;
}

declare module '*.yml' {
  const value: Record<string, string>;
  export default value;
}