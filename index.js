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

function zipByDecode(acc, [k, v]) {
  acc[k.trim()] = decodeURIComponent(v)
  return acc
}

async function handleRequest(request) {
  const url = new URL(request.url)

  // Disallow crawlers
  if (url.pathname === '/robots.txt') {
    return new Response('User-agent: *\nDisallow: /', { status: 200 })
  }

  const qs = url.search
    .slice(1)
    .split('&')
    .map((x) => x.split('='))
    .reduce(zipByDecode, {})

  const shouldOnDomainProxy = !!qs.odp
  if (shouldOnDomainProxy) {
    return fetch(qs.odp.replace(/^\/\//, 'https://'), request)
  }

  const cookies = (request.headers.get('cookie') || '')
    .split(';')
    .map((x) => x.split('='))
    .reduce(zipByDecode, {})

  const config = [
    'x-host',
    'x-link',
    'x-async',
    'x-defer',
    'x-no-async-hide',
    'x-bypass-transform',
    'x-push',
    'x-on-domain',
  ]
    .map((k) => [k, request.headers.get(k) || cookies[k]])
    .reduce((acc, [k, v]) => {
      acc[k] = v
      return acc
    }, {})

  // When overrideHost is used in a script, WPT sets x-host to original host i.e. site we want to proxy
  const host = config['x-host']

  // Error if x-host header missing
  if (!host) {
    return fetch('https://charlespwd.github.io/faster')
  }

  const requestHost = url.hostname
  url.hostname = host

  const bypassTransform = config['x-bypass-transform']
  const acceptHeader = request.headers.get('accept')

  const isHtmlRequest =
    acceptHeader &&
    (acceptHeader.includes('text/html') || acceptHeader.includes('*/*'))
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
  const domains = config['x-on-domain']

  const response = await getResponse(req, shouldPush)

  // Add the link header
  if (linkHeader) response.headers.append('Link', linkHeader)

  // Fancy pantsy way of turning on/off features and applying them on an
  // HTMLRewriter. Stored as [fnName, ...args][].
  const commands = [
    asyncHide && ['on', 'head > style', new AsyncHideHandler()],
    deferSelector && ['on', deferSelector, new AttrHandler('defer', true)],
    asyncSelector && ['on', asyncSelector, new AttrHandler('async', true)],
    domains && [
      'on',
      'script[src],link[href][rel=stylesheet],link[href][rel=preload],link[href][rel*=icon],[src],[data-srcset],[data-src]',
      new OnDomainHandler(domains, url.hostname),
    ],
    domains && [
      'on',
      'link[href][rel=preconnect],link[href][rel=dns-prefetch]',
      new DeleteNodeHandler(),
    ],
    ['transform', response],
  ].filter(Boolean)

  // Apply all the commands on the HTMLRewriter and send.
  return commands.reduce((rewriter, [fnName, ...args]) => {
    return rewriter[fnName](...args)
  }, new HTMLRewriter())
}

class DeleteNodeHandler {
  element(element) {
    console.log('removing element', element);
    element.remove();
  }
}

// This special regex matches two collocated regexes because special sites
// like gymshark do weird proxying of their own. It's a double proxy...
const urlRegex = /((https?:)?\/\/([-a-zA-Z0-9@:%._\+~#=]{1,256}\.)+[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=,]*)\/?)+/gm
const replacer = match => `/?odp=${encodeURIComponent(match)}`;

class OnDomainHandler {
  constructor(domains, host) {
    this.domains = domains
      .split(',')
      .map((domain) => new RegExp(domain.replace(/\./g, '.').replace(/\*/g, 'w*')))
    this.host = host
  }
  element(element) {
    const attrs = ['href', 'src', 'srcset', 'data-srcset', 'data-src'].filter(element.getAttribute.bind(element));
    for (const attr of attrs) {
      const attrValue = element.getAttribute(attr)
      const shouldReplace = !!this.domains.find((domain) => domain.test(attrValue))
      if (!shouldReplace) return
      element.setAttribute(attr, attrValue.replace(urlRegex, replacer));
    }
  }
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
