/**
 * Configurable WebPageTest Cloudflare Worker.
 *
 * Options (sent as headers)
 *  - `x-no-async-hide: true    `: disables Google Optimize anti-flicker snippet
 *  - `x-async: <cssSelector>   `: add `async="true"` to nodes targeted by css selector
 *  - `x-bypass-transform: true `: disable all transformations
 *  - `x-defer: <cssSelector>   `: add `defer="true"` to nodes targeted by css selector
 *  - `x-link: <linkHeader>     `: preconnect & preloads you'd want to add to the response
 *  - `x-push: true             `: enables header streaming while we wait for the response
 */

addEventListener('fetch', (event) => {
  event.respondWith(handleRequest(event.request))
})

async function getResponse(request, shouldPush) {
  // If push of headers is not enabled, return a copy of the response
  // (so we can mutate the headers).
  if (!shouldPush) {
    const response = await fetch(request)
    return new Response(response.body, response)
  }

  // Allow for pushing HTTP headers while we wait for the response
  const { readable, writable } = new TransformStream()

  fetch(request).then((response) => {
    response.body.pipeTo(writable)
  })

  const allHeaders = [
    ['connection', 'keep-alive'],
    ['content-language', 'en'],
    [
      'content-security-policy',
      "block-all-mixed-content; frame-ancestors 'none'; upgrade-insecure-requests;",
    ],
    ['content-type', 'text/html; charset=utf-8'],
    ['server', 'cloudflare'],
    ['strict-transport-security', 'max-age=7889238'],
    ['vary', 'Accept'],
    ['x-frame-options', 'DENY'],
    ['x-permitted-cross-domain-policies', 'none'],
    ['x-xss-protection', '1; mode=block'],
  ]

  const headers = new Headers()

  for (const [k, v] of allHeaders) {
    headers.append(k, v)
  }

  return new Response(readable, {
    status: 200,
    statusText: 'OK',
    headers: headers,
  })
}

async function handleRequest(request) {
  const url = new URL(request.url)

  // Disallow crawlers
  if (url.pathname === '/robots.txt') {
    return new Response('User-agent: *\nDisallow: /', { status: 200 })
  }

  const cookies = (request.headers.get('cookie') || '')
    .split(';')
    .map((x) => x.split('='))
    .reduce((acc, [k, v]) => {
      acc[k.trim()] = decodeURIComponent(v)
      return acc
    }, {})

  const config = [
    'x-host',
    'x-link',
    'x-async',
    'x-defer',
    'x-no-async-hide',
    'x-bypass-transform',
    'x-push',
  ]
    .map((k) => [k, request.headers.get(k) || cookies[k]])
    .reduce((acc, [k, v]) => {
      acc[k] = v
      return acc
    }, {})

  // When overrideHost is used in a script, WPT sets x-host to original host i.e. site we want to proxy
  const host = config['x-host']
  console.log(host, config, cookies);

  // Error if x-host header missing
  if (!host) {
    return fetch('https://charlespwd.github.io/faster')
  }

  url.hostname = host

  const bypassTransform = config['x-bypass-transform']
  const acceptHeader = request.headers.get('accept')

  const isHtmlRequest = acceptHeader && (acceptHeader.includes('text/html') || acceptHeader.includes('*/*'));
  const shouldBypassTransform =
    bypassTransform && bypassTransform.indexOf('true') !== -1
  const shouldTransform = isHtmlRequest && !shouldBypassTransform

  const req = new Request(url, request)
  req.headers.delete('x-host')
  req.headers.delete('x-forwarded-proto')
  req.headers.delete('cf-visitor')
  req.headers.delete('cf-workers-preview-token')

  if (!shouldTransform) {
    // Just proxy the request
    return fetch(url, req)
  }

  const linkHeader = config['x-link']
  const asyncSelector = config['x-async']
  const deferSelector = config['x-defer']
  const asyncHide = config['x-no-async-hide'] === 'true'
  const shouldPush = config['x-push'] !== 'true'

  const response = await getResponse(req, shouldPush)

  // Add the link header
  if (linkHeader) response.headers.append('Link', linkHeader)

  // Fancy pantsy way of turning on/off features and applying them on an
  // HTMLRewriter. Stored as [fnName, ...args][].
  const commands = [
    asyncHide && ['on', 'head > style', new AsyncHideHandler()],
    deferSelector && ['on', deferSelector, new AttrHandler('defer', true)],
    asyncSelector && ['on', asyncSelector, new AttrHandler('async', true)],
    ['transform', response],
  ].filter(Boolean)

  // Apply all the commands on the HTMLRewriter and send.
  return commands.reduce((rewriter, [fnName, ...args]) => {
    return rewriter[fnName](...args)
  }, new HTMLRewriter())
}

class AsyncHideHandler {
  text(text) {
    text.replace(text.text.replace(/async-hide/, 'async-hide-noop'))
  }
}

class AttrHandler {
  constructor(attribute, value = true) {
    this._attribute = attribute
    this._value = value
  }
  element(element) {
    element.setAttribute(this._attribute, this._value)
  }
}
