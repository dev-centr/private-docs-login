import { hostOf } from "./codec.mjs"

export function groupsFromMemberLists(groups, membersById, optInUsername) {
  return groups
    .filter((group) => (membersById[group.id] || []).some((member) => member.username === optInUsername))
    .map((group) => group.full_path)
}

export async function listOptedInGroups({ fetchImpl, instanceUrl, accessToken, optInUsername }) {
  const root = instanceUrl.replace(/\/$/, "")
  const headers = { authorization: `Bearer ${accessToken}`, accept: "application/json" }
  const groups = []
  for (let page = 1; page <= 20; page += 1) {
    const url = `${root}/api/v4/groups?membership=true&min_access_level=10&per_page=100&page=${page}`
    const res = await fetchImpl(url, { headers })
    if (!res.ok) throw new Error(`GitLab groups responded ${res.status}`)
    const batch = await res.json()
    groups.push(...batch)
    if (!Array.isArray(batch) || batch.length < 100) break
  }
  const membersById = {}
  for (const group of groups) {
    const url = `${root}/api/v4/groups/${encodeURIComponent(group.id)}/members/all?query=${encodeURIComponent(optInUsername)}&per_page=100`
    const res = await fetchImpl(url, { headers })
    if (!res.ok) {
      membersById[group.id] = []
      continue
    }
    const members = await res.json()
    membersById[group.id] = Array.isArray(members) ? members : []
  }
  return groupsFromMemberLists(groups, membersById, optInUsername)
}

export function createGitlabForge(options) {
  const root = options.instanceUrl.replace(/\/$/, "")
  return {
    id: "gitlab",
    label: `GitLab (${hostOf(root)})`,
    host: hostOf(root),
    instanceUrl: root,
    optInUsername: options.optInUsername,
    async authorizationUrl({ redirectUri, state }) {
      const url = new URL(`${root}/oauth/authorize`)
      url.searchParams.set("client_id", options.clientId)
      url.searchParams.set("redirect_uri", redirectUri)
      url.searchParams.set("response_type", "code")
      url.searchParams.set("state", state)
      url.searchParams.set("scope", "read_api")
      return url.toString()
    },
    async complete({ code, redirectUri }) {
      const tokenRes = await options.fetchImpl(`${root}/oauth/token`, {
        method: "POST",
        headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: options.clientId,
          client_secret: options.clientSecret,
          code,
          grant_type: "authorization_code",
          redirect_uri: redirectUri,
        }),
      })
      if (!tokenRes.ok) throw new Error(`GitLab token responded ${tokenRes.status}`)
      const token = await tokenRes.json()
      if (!token.access_token) throw new Error("GitLab token response had no access token")
      const userRes = await options.fetchImpl(`${root}/api/v4/user`, {
        headers: { authorization: `Bearer ${token.access_token}`, accept: "application/json" },
      })
      if (!userRes.ok) throw new Error(`GitLab user responded ${userRes.status}`)
      const user = await userRes.json()
      const groups = await listOptedInGroups({
        fetchImpl: options.fetchImpl,
        instanceUrl: root,
        accessToken: token.access_token,
        optInUsername: options.optInUsername,
      })
      return {
        subject: String(user.id),
        username: user.username || "",
        // GitLab's primary address must be confirmed before it is the account email.
        email: user.email && user.confirmed_at ? String(user.email) : "",
        emailVerified: Boolean(user.email && user.confirmed_at),
        groups,
      }
    },
  }
}
