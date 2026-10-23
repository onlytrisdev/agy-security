export function parseGitRemote(remote) {
  if (remote.includes("://")) {
    const url = new URL(remote);
    return {
      url,
      path: url.pathname.slice(1),
      scpStyle: false
    };
  }
  const scp = /^((?:[^@/:\s?#]+@)?(?:\[[^\]]+\]|[^@/:\s?#]+)):(.+)$/u.exec(remote);
  if (scp === null) {
    return undefined;
  }
  return {
    url: new URL(`ssh://${scp[1]}`),
    path: scp[2],
    scpStyle: true
  };
}

export function isGitHubCloudHost(host) {
  return host === "github.com" || host.endsWith(".ghe.com");
}
