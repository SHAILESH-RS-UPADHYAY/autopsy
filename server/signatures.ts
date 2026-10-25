// Technology fingerprints. Each check names one piece of evidence; weights add
// up to a confidence (≥1 confirmed, ≥0.6 probable, otherwise trace). The first
// capture group of a pattern, when present, is read as a version.

export type Category =
  | 'framework' | 'cms' | 'styling' | 'library' | 'build' | 'hosting' | 'server'
  | 'data' | 'auth' | 'commerce' | 'analytics' | 'support' | 'monitoring' | 'security' | 'email' | 'media';

export const CATEGORIES: Record<Category, string> = {
  framework: 'Framework & rendering',
  cms: 'CMS & site builders',
  styling: 'Styling & UI kits',
  library: 'Front-end libraries',
  build: 'Build tooling',
  hosting: 'Hosting, CDN & edge',
  server: 'Web server & backend',
  data: 'Data, content & APIs',
  auth: 'Authentication',
  commerce: 'Commerce & payments',
  analytics: 'Analytics & marketing',
  support: 'Support & engagement',
  monitoring: 'Monitoring',
  security: 'Security & certificates',
  email: 'DNS, email & domain',
  media: 'Fonts & media',
};

export type Source = 'header' | 'cookie' | 'meta' | 'html' | 'script' | 'stylesheet' | 'js' | 'css' | 'dns' | 'tls' | 'url';

export interface Check {
  source: Source;
  key?: string | RegExp; // header/cookie/meta name, dns record type, tls field
  pattern?: RegExp;
  weight: number;
}

export interface Rule {
  id: string;
  name: string;
  category: Category;
  url: string;
  checks: Check[];
  implies?: string[];
}

const c = (source: Source, key: Check['key'], pattern?: RegExp, weight = 1): Check => ({ source, key, pattern, weight });
const header = (key: string | RegExp, pattern?: RegExp, w = 1) => c('header', key, pattern, w);
const cookie = (key: RegExp, w = 0.8) => c('cookie', key, undefined, w);
const meta = (key: string, pattern: RegExp, w = 1) => c('meta', key, pattern, w);
const html = (pattern: RegExp, w = 0.6) => c('html', undefined, pattern, w);
const script = (pattern: RegExp, w = 0.9) => c('script', undefined, pattern, w);
const sheet = (pattern: RegExp, w = 0.9) => c('stylesheet', undefined, pattern, w);
const js = (pattern: RegExp, w = 0.6) => c('js', undefined, pattern, w);
const css = (pattern: RegExp, w = 0.8) => c('css', undefined, pattern, w);
const dns = (key: 'a' | 'aaaa' | 'cname' | 'ns' | 'mx' | 'txt', pattern: RegExp, w = 0.9) => c('dns', key, pattern, w);
const tls = (key: 'issuer' | 'alpn', pattern: RegExp, w = 1) => c('tls', key, pattern, w);
const url = (pattern: RegExp, w = 1) => c('url', undefined, pattern, w);
// Third-party snippets show up either as a script URL or inline loader code.
const asset = (pattern: RegExp, w = 1) => [script(pattern, w), html(pattern, w)];

const rule = (id: string, name: string, category: Category, site: string, checks: (Check | Check[])[], implies?: string[]): Rule =>
  ({ id, name, category, url: site, checks: checks.flat(), implies });

export const RULES: Rule[] = [
  /* Frameworks */
  rule('nextjs', 'Next.js', 'framework', 'https://nextjs.org', [
    html(/<script id="__NEXT_DATA__"/, 1), html(/self\.__next_f\.push/, 1), script(/\/_next\/static\//, 0.9),
    header('x-powered-by', /Next\.js ?([\d.]+)?/), header(/^x-nextjs-/, undefined, 1), html(/\/_next\/image\?url=/, 0.5),
  ], ['react']),
  rule('react', 'React', 'framework', 'https://react.dev', [
    js(/__REACT_DEVTOOLS_GLOBAL_HOOK__|react\.(?:transitional\.)?element|react-dom\.production/, 0.9),
    html(/data-reactroot|data-reactid/, 0.9),
  ]),
  rule('remix', 'Remix / React Router', 'framework', 'https://reactrouter.com', [
    html(/__remixContext|__reactRouterContext|__remixManifest/, 1),
  ], ['react']),
  rule('gatsby', 'Gatsby', 'framework', 'https://www.gatsbyjs.com', [html(/id="___gatsby"/, 1), meta('generator', /Gatsby ?([\d.]+)?/)], ['react']),
  rule('nuxt', 'Nuxt', 'framework', 'https://nuxt.com', [
    html(/window\.__NUXT__|id="__NUXT_DATA__"|id="__nuxt"/, 1), script(/\/_nuxt\//, 0.9), header('x-powered-by', /Nuxt/),
  ], ['vue']),
  rule('vue', 'Vue', 'framework', 'https://vuejs.org', [
    html(/\sdata-v-[0-9a-f]{8}\b|data-server-rendered="true"/, 0.9), js(/__VUE_PROD_DEVTOOLS__|__vue_app__|\[Vue warn\]/, 0.8),
  ]),
  rule('angular', 'Angular', 'framework', 'https://angular.dev', [html(/ng-version="([\d.]+)"/, 1), html(/_nghost-|_ngcontent-/, 0.8), js(/ngDevMode|ɵcmp/, 0.6)]),
  rule('sveltekit', 'SvelteKit', 'framework', 'https://svelte.dev/docs/kit', [html(/data-sveltekit-|__sveltekit_/, 1), script(/\/_app\/immutable\//, 0.9)], ['svelte']),
  rule('svelte', 'Svelte', 'framework', 'https://svelte.dev', [html(/class="[^"]*\bsvelte-[a-z0-9]{5,}\b/, 0.8)]),
  rule('astro', 'Astro', 'framework', 'https://astro.build', [
    html(/<astro-island|data-astro-cid-|<astro-slot/, 1), meta('generator', /Astro v?([\d.]+)/), script(/\/_astro\//, 0.8),
  ]),
  rule('solid', 'SolidJS', 'framework', 'https://www.solidjs.com', [html(/_\$HY\b|data-hk=/, 0.9)]),
  rule('qwik', 'Qwik', 'framework', 'https://qwik.dev', [html(/q:container=|qwikloader/, 1)]),
  rule('preact', 'Preact', 'framework', 'https://preactjs.com', [js(/__PREACT_DEVTOOLS__/, 1)]),
  rule('ember', 'Ember', 'framework', 'https://emberjs.com', [html(/id="ember\d+"/, 0.8), js(/Ember\.VERSION/, 1)]),
  rule('phoenix', 'Phoenix LiveView', 'framework', 'https://www.phoenixframework.org', [html(/data-phx-main|data-phx-session/, 1)]),
  rule('hotwire', 'Hotwire Turbo', 'framework', 'https://hotwired.dev', [html(/<turbo-frame|data-turbo-/, 0.9)]),
  rule('htmx', 'htmx', 'library', 'https://htmx.org', [html(/\shx-(?:get|post|target|swap|trigger)=/, 1), script(/htmx(?:\.min)?\.js/, 1)]),
  rule('alpine', 'Alpine.js', 'library', 'https://alpinejs.dev', [html(/\sx-data=|\sx-init=/, 0.8), script(/alpinejs/i, 1)]),
  rule('jquery', 'jQuery', 'library', 'https://jquery.com', [script(/jquery[-.]?(\d+\.\d+(?:\.\d+)?)?(?:\.min)?\.js/i, 1), js(/jQuery v(\d+\.\d+\.\d+)/, 1)]),

  /* CMS & builders */
  rule('wordpress', 'WordPress', 'cms', 'https://wordpress.org', [
    html(/\/wp-content\/|\/wp-includes\//, 1), meta('generator', /WordPress ?([\d.]+)?/), header('link', /api\.w\.org/), cookie(/^wordpress_|^wp-settings-/),
  ], ['php']),
  rule('woocommerce', 'WooCommerce', 'commerce', 'https://woocommerce.com', [html(/\/plugins\/woocommerce\/|woocommerce-/, 1)], ['wordpress']),
  rule('webflow', 'Webflow', 'cms', 'https://webflow.com', [
    html(/data-wf-page=|data-wf-site=/, 1), meta('generator', /Webflow/), url(/\.webflow\.io$/),
  ]),
  rule('framer', 'Framer', 'cms', 'https://www.framer.com', [html(/framerusercontent\.com|data-framer-/, 1), meta('generator', /Framer ?([\w.]+)?/), url(/\.framer\.(?:website|app)$/)]),
  rule('wix', 'Wix', 'cms', 'https://www.wix.com', [html(/static\.parastorage\.com|static\.wixstatic\.com/, 1), header('x-wix-request-id'), meta('generator', /Wix\.com/)]),
  rule('squarespace', 'Squarespace', 'cms', 'https://www.squarespace.com', [html(/static1\.squarespace\.com|Static\.SQUARESPACE_CONTEXT/, 1), header('server', /Squarespace/)]),
  rule('ghost', 'Ghost', 'cms', 'https://ghost.org', [meta('generator', /Ghost ?([\d.]+)?/), header(/^x-ghost-/)]),
  rule('drupal', 'Drupal', 'cms', 'https://www.drupal.org', [header('x-generator', /Drupal ?(\d+)?/), html(/drupal-settings-json|Drupal\.settings/, 1)], ['php']),
  rule('docusaurus', 'Docusaurus', 'cms', 'https://docusaurus.io', [meta('generator', /Docusaurus v?([\d.]+)/), html(/__docusaurus/, 0.9)], ['react']),
  rule('vitepress', 'VitePress', 'cms', 'https://vitepress.dev', [meta('generator', /VitePress v?([\d.]+)?/), html(/__VP_HASH_MAP__/, 1)], ['vue']),
  rule('hugo', 'Hugo', 'cms', 'https://gohugo.io', [meta('generator', /Hugo ([\d.]+)/)]),
  rule('jekyll', 'Jekyll', 'cms', 'https://jekyllrb.com', [meta('generator', /Jekyll v?([\d.]+)/)]),
  rule('eleventy', 'Eleventy', 'cms', 'https://www.11ty.dev', [meta('generator', /Eleventy v?([\d.]+)/)]),
  rule('contentful', 'Contentful', 'data', 'https://www.contentful.com', [html(/images\.ctfassets\.net|cdn\.contentful\.com/, 1)]),
  rule('sanity', 'Sanity', 'data', 'https://www.sanity.io', [html(/cdn\.sanity\.io/, 1)]),
  rule('prismic', 'Prismic', 'data', 'https://prismic.io', [html(/images\.prismic\.io|cdn\.prismic\.io/, 1)]),
  rule('storyblok', 'Storyblok', 'data', 'https://www.storyblok.com', [html(/a\.storyblok\.com/, 1)]),
  rule('datocms', 'DatoCMS', 'data', 'https://www.datocms.com', [html(/datocms-assets\.com/, 1)]),
  rule('strapi', 'Strapi', 'data', 'https://strapi.io', [header('x-powered-by', /Strapi/)]),

  /* Styling */
  rule('tailwind', 'Tailwind CSS', 'styling', 'https://tailwindcss.com', [
    css(/tailwindcss v?([\d.]+)/, 1), css(/--tw-(?:ring|shadow|translate|border-spacing)/, 0.9),
    html(/class="[^"]*\b(?:sm|md|lg|xl):(?:flex|grid|hidden|block|px-\d|text-\w+)/, 0.5),
  ]),
  rule('bootstrap', 'Bootstrap', 'styling', 'https://getbootstrap.com', [
    css(/Bootstrap\s+v([\d.]+)/, 1), script(/bootstrap(?:\.bundle)?(?:\.min)?\.js/, 0.9), sheet(/bootstrap(?:\.min)?\.css/, 0.9),
    html(/class="[^"]*\b(?:navbar-expand-(?:sm|md|lg|xl)|col-(?:sm|md|lg)-\d+)\b/, 0.6),
  ]),
  rule('bulma', 'Bulma', 'styling', 'https://bulma.io', [css(/bulma\.io|bulma v?([\d.]+)/i, 1)]),
  rule('mui', 'Material UI', 'styling', 'https://mui.com', [html(/class="[^"]*\bMui[A-Z]\w+-root/, 1)], ['emotion', 'react']),
  rule('chakra', 'Chakra UI', 'styling', 'https://chakra-ui.com', [html(/--chakra-|class="[^"]*\bchakra-/, 1)], ['react']),
  rule('radix', 'Radix UI', 'styling', 'https://www.radix-ui.com', [html(/data-radix-|radix-:/, 0.8)], ['react']),
  rule('styled-components', 'styled-components', 'styling', 'https://styled-components.com', [html(/<style[^>]+data-styled/, 1)]),
  rule('emotion', 'Emotion', 'styling', 'https://emotion.sh', [html(/<style[^>]+data-emotion/, 1)]),
  rule('fontawesome', 'Font Awesome', 'media', 'https://fontawesome.com', [asset(/kit\.fontawesome\.com|font-?awesome/i, 0.9)]),
  rule('google-fonts', 'Google Fonts', 'media', 'https://fonts.google.com', [html(/fonts\.googleapis\.com|fonts\.gstatic\.com/, 1)]),
  rule('adobe-fonts', 'Adobe Fonts', 'media', 'https://fonts.adobe.com', [html(/use\.typekit\.net|p\.typekit\.net/, 1)]),
  rule('cloudinary', 'Cloudinary', 'media', 'https://cloudinary.com', [html(/res\.cloudinary\.com/, 1)]),
  rule('imgix', 'imgix', 'media', 'https://imgix.com', [html(/\.imgix\.net\//, 1)]),

  /* Libraries */
  rule('gsap', 'GSAP', 'library', 'https://gsap.com', [script(/gsap|greensock/i, 1), js(/GreenSock|ScrollTrigger/, 0.9)]),
  rule('threejs', 'Three.js', 'library', 'https://threejs.org', [script(/three(?:\.module)?(?:\.min)?\.js/, 0.9), js(/WebGLRenderer|THREE\.REVISION/, 0.8)]),
  rule('lottie', 'Lottie', 'library', 'https://airbnb.io/lottie', [asset(/lottie(?:-web|-player|files)?|bodymovin|dotlottie/i, 0.9)]),
  rule('framer-motion', 'Motion (Framer Motion)', 'library', 'https://motion.dev', [js(/framer-motion|data-projection-id/, 0.6)]),
  rule('swiper', 'Swiper', 'library', 'https://swiperjs.com', [asset(/swiper(?:-bundle)?(?:\.min)?\.(?:js|css)/, 0.9), html(/class="swiper[\s"]/, 0.6)]),
  rule('lodash', 'Lodash', 'library', 'https://lodash.com', [js(/__lodash_hash_undefined__/, 1)]),
  rule('redux', 'Redux', 'library', 'https://redux.js.org', [js(/@@redux\/INIT|__REDUX_DEVTOOLS_EXTENSION/, 1)]),
  rule('apollo', 'Apollo Client', 'data', 'https://www.apollographql.com', [html(/__APOLLO_STATE__/, 1), js(/__APOLLO_CLIENT__/, 1)], ['graphql']),
  rule('graphql', 'GraphQL', 'data', 'https://graphql.org', [js(/__typename/, 0.6), js(/\/graphql["'?]/, 0.5)]),
  rule('socketio', 'Socket.IO', 'data', 'https://socket.io', [asset(/socket\.io(?:\.min)?\.js/, 1), js(/engine\.io|EIO=4/, 0.6)]),
  rule('pwa', 'Web App Manifest', 'build', 'https://web.dev/learn/pwa', [html(/<link[^>]+rel=["']manifest["']/, 0.9), js(/serviceWorker\.register/, 0.5)]),

  /* Build */
  rule('webpack', 'webpack', 'build', 'https://webpack.js.org', [js(/webpackChunk|__webpack_require__/, 1)]),
  rule('vite', 'Vite', 'build', 'https://vite.dev', [
    html(/<script type="module" crossorigin src="[^"]*\/assets\/index-[\w-]{8}\.js"/, 0.9), js(/relList\.supports\("modulepreload"\)/, 0.6),
  ]),

  /* Hosting & edge */
  rule('cloudflare', 'Cloudflare', 'hosting', 'https://www.cloudflare.com', [
    header('server', /cloudflare/i), header('cf-ray'), cookie(/^__cf_bm$|^cf_clearance$/), dns('ns', /\.ns\.cloudflare\.com$/, 1), html(/\/cdn-cgi\//, 0.5),
  ]),
  rule('cloudflare-pages', 'Cloudflare Pages', 'hosting', 'https://pages.cloudflare.com', [url(/\.pages\.dev$/), dns('cname', /\.pages\.dev$/)], ['cloudflare']),
  rule('vercel', 'Vercel', 'hosting', 'https://vercel.com', [
    header('server', /^Vercel$/i), header(/^x-vercel-/), dns('cname', /vercel-dns\.com|\.vercel\.app$/, 1), dns('a', /^76\.76\.21\.\d+$/, 0.8), url(/\.vercel\.app$/),
  ]),
  rule('netlify', 'Netlify', 'hosting', 'https://www.netlify.com', [header('server', /Netlify/i), header('x-nf-request-id'), dns('cname', /netlify\.(?:app|com)$/, 1), url(/\.netlify\.app$/)]),
  rule('cloudfront', 'Amazon CloudFront', 'hosting', 'https://aws.amazon.com/cloudfront', [header(/^x-amz-cf-(?:id|pop)$/), header('via', /CloudFront/i), dns('cname', /cloudfront\.net$/, 1)]),
  rule('s3', 'Amazon S3', 'hosting', 'https://aws.amazon.com/s3', [header('server', /AmazonS3/), header('x-amz-request-id', undefined, 0.6)]),
  rule('aws-elb', 'AWS Elastic Load Balancing', 'hosting', 'https://aws.amazon.com/elasticloadbalancing', [header('server', /^awselb/), cookie(/^AWSALB/, 0.9)]),
  rule('route53', 'Amazon Route 53', 'email', 'https://aws.amazon.com/route53', [dns('ns', /awsdns/, 1)]),
  rule('google-cloud', 'Google Cloud', 'hosting', 'https://cloud.google.com', [header('server', /Google Frontend/), header('via', /1\.1 google/, 0.8), header('x-cloud-trace-context', undefined, 0.8)]),
  rule('firebase-hosting', 'Firebase Hosting', 'hosting', 'https://firebase.google.com/products/hosting', [url(/\.(?:web\.app|firebaseapp\.com)$/), dns('cname', /\.web\.app$|firebaseapp\.com$/)]),
  rule('fastly', 'Fastly', 'hosting', 'https://www.fastly.com', [header(/^x-fastly-/), header('x-served-by', /^cache-/, 0.8), header('via', /varnish/i, 0.5)]),
  rule('akamai', 'Akamai', 'hosting', 'https://www.akamai.com', [header(/^x-akamai-|^akamai-/), header('server', /AkamaiGHost|AkamaiNetStorage/), dns('cname', /edgekey\.net|akamaiedge\.net|edgesuite\.net/, 1)]),
  rule('azure', 'Microsoft Azure', 'hosting', 'https://azure.microsoft.com', [header(/^x-azure-ref$|^x-msedge-ref$/), dns('cname', /azurewebsites\.net|azureedge\.net|azurefd\.net|trafficmanager\.net/, 1)]),
  rule('github-pages', 'GitHub Pages', 'hosting', 'https://pages.github.com', [header('server', /^GitHub\.com$/), dns('cname', /\.github\.io$/, 1), dns('a', /^185\.199\.(?:108|109|110|111)\.153$/, 0.9), url(/\.github\.io$/)]),
  rule('render', 'Render', 'hosting', 'https://render.com', [header(/^rndr-id$|^x-render-origin-server$/), dns('cname', /onrender\.com$/, 1), url(/\.onrender\.com$/)]),
  rule('fly', 'Fly.io', 'hosting', 'https://fly.io', [header('fly-request-id'), header('server', /^Fly\//), dns('cname', /\.fly\.dev$/, 1), url(/\.fly\.dev$/)]),
  rule('railway', 'Railway', 'hosting', 'https://railway.com', [header(/^x-railway-/), url(/\.up\.railway\.app$/)]),
  rule('heroku', 'Heroku', 'hosting', 'https://www.heroku.com', [header('via', /vegur/i, 0.9), dns('cname', /herokuapp\.com|herokudns\.com/, 1), url(/\.herokuapp\.com$/)]),
  rule('deno-deploy', 'Deno Deploy', 'hosting', 'https://deno.com/deploy', [header('server', /^deno\//i)]),
  rule('bunny', 'bunny.net', 'hosting', 'https://bunny.net', [header('server', /BunnyCDN/i), header('cdn-requestid', undefined, 0.8)]),
  rule('shopify', 'Shopify', 'commerce', 'https://www.shopify.com', [
    html(/cdn\.shopify\.com|Shopify\.theme/, 1), header(/^x-shopid$|^x-shopify-/), header('powered-by', /Shopify/), cookie(/^_shopify_/), url(/\.myshopify\.com$/),
  ]),
  rule('http3', 'HTTP/3', 'hosting', 'https://en.wikipedia.org/wiki/HTTP/3', [header('alt-svc', /\bh3\b/)]),
  rule('http2', 'HTTP/2', 'hosting', 'https://en.wikipedia.org/wiki/HTTP/2', [tls('alpn', /^h2$/)]),

  /* Server */
  rule('nginx', 'nginx', 'server', 'https://nginx.org', [header('server', /^nginx\/?([\d.]+)?/i)]),
  rule('openresty', 'OpenResty', 'server', 'https://openresty.org', [header('server', /openresty\/?([\d.]+)?/i)]),
  rule('apache', 'Apache HTTP Server', 'server', 'https://httpd.apache.org', [header('server', /^Apache\/?([\d.]+)?/)]),
  rule('litespeed', 'LiteSpeed', 'server', 'https://www.litespeedtech.com', [header('server', /LiteSpeed/i)]),
  rule('caddy', 'Caddy', 'server', 'https://caddyserver.com', [header('server', /^Caddy/)]),
  rule('iis', 'Microsoft IIS', 'server', 'https://www.iis.net', [header('server', /Microsoft-IIS\/?([\d.]+)?/)]),
  rule('envoy', 'Envoy', 'server', 'https://www.envoyproxy.io', [header('server', /^envoy$/), header(/^x-envoy-/)]),
  rule('uvicorn', 'Uvicorn / Gunicorn', 'server', 'https://www.uvicorn.org', [header('server', /uvicorn|gunicorn/i)]),
  rule('express', 'Express', 'server', 'https://expressjs.com', [header('x-powered-by', /^Express$/)], ['nodejs']),
  rule('nodejs', 'Node.js', 'server', 'https://nodejs.org', [header('x-powered-by', /Node/)]),
  rule('php', 'PHP', 'server', 'https://www.php.net', [header('x-powered-by', /PHP\/?([\d.]+)?/), cookie(/^PHPSESSID$/)]),
  rule('laravel', 'Laravel', 'server', 'https://laravel.com', [cookie(/^laravel_session$/, 1)], ['php']),
  rule('django', 'Django', 'server', 'https://www.djangoproject.com', [html(/name="csrfmiddlewaretoken"/, 1), cookie(/^csrftoken$|^django_language$/, 0.6)]),
  rule('rails', 'Ruby on Rails', 'server', 'https://rubyonrails.org', [html(/<meta[^>]+content="authenticity_token"/, 1), header('x-runtime', undefined, 0.3)]),
  rule('aspnet', 'ASP.NET', 'server', 'https://dotnet.microsoft.com/apps/aspnet', [header('x-powered-by', /ASP\.NET/), header('x-aspnet-version', /([\d.]+)/), cookie(/^ASP\.NET_SessionId$|^\.AspNetCore\./), html(/__VIEWSTATE/, 1)]),
  rule('java', 'Java servlet container', 'server', 'https://jakarta.ee', [cookie(/^JSESSIONID$/, 0.9)]),

  /* Data, auth, commerce */
  rule('firebase', 'Firebase', 'data', 'https://firebase.google.com', [asset(/gstatic\.com\/firebasejs|firebaseio\.com|firestore\.googleapis\.com/, 1), js(/firebaseapp\.com|firestore\.googleapis\.com/, 0.8)]),
  rule('supabase', 'Supabase', 'data', 'https://supabase.com', [html(/[a-z0-9]{20}\.supabase\.co/, 1), js(/\.supabase\.co\b|supabase-js/, 1)]),
  rule('algolia', 'Algolia', 'data', 'https://www.algolia.com', [asset(/algolia(?:net)?\.(?:net|com)|algoliasearch/, 1), js(/algolia\.net/, 0.9)]),
  rule('mapbox', 'Mapbox', 'data', 'https://www.mapbox.com', [asset(/api\.mapbox\.com|mapbox-gl/, 1)]),
  rule('google-maps', 'Google Maps', 'data', 'https://developers.google.com/maps', [asset(/maps\.googleapis\.com/, 1)]),
  rule('clerk', 'Clerk', 'auth', 'https://clerk.com', [asset(/clerk\.(?:[\w-]+\.)*(?:accounts\.dev|com)\/npm\/@clerk|clerk-js/, 1), cookie(/^__client_uat|^__session$/, 0.8)]),
  rule('auth0', 'Auth0', 'auth', 'https://auth0.com', [asset(/cdn\.auth0\.com|auth0-spa-js/, 1), js(/\.auth0\.com/, 0.7)]),
  rule('nextauth', 'Auth.js (NextAuth)', 'auth', 'https://authjs.dev', [cookie(/next-auth\.|authjs\./, 1)]),
  rule('stripe', 'Stripe', 'commerce', 'https://stripe.com', [asset(/js\.stripe\.com/, 1)]),
  rule('paypal', 'PayPal', 'commerce', 'https://www.paypal.com', [asset(/paypal\.com\/sdk\/js|paypalobjects\.com/, 1)]),
  rule('razorpay', 'Razorpay', 'commerce', 'https://razorpay.com', [asset(/checkout\.razorpay\.com/, 1)]),
  rule('paddle', 'Paddle', 'commerce', 'https://www.paddle.com', [asset(/cdn\.paddle\.com/, 1)]),
  rule('lemonsqueezy', 'Lemon Squeezy', 'commerce', 'https://www.lemonsqueezy.com', [asset(/lemonsqueezy\.com|lmsqueezy/, 1)]),
  rule('bigcommerce', 'BigCommerce', 'commerce', 'https://www.bigcommerce.com', [html(/cdn\d*\.bigcommerce\.com/, 1)]),
  rule('magento', 'Magento / Adobe Commerce', 'commerce', 'https://business.adobe.com/products/magento/magento-commerce.html', [html(/text\/x-magento-init|Magento_/, 1)], ['php']),
  rule('klaviyo', 'Klaviyo', 'analytics', 'https://www.klaviyo.com', [asset(/static\.klaviyo\.com/, 1)]),

  /* Analytics & marketing */
  rule('ga4', 'Google Analytics 4', 'analytics', 'https://marketingplatform.google.com/about/analytics', [script(/googletagmanager\.com\/gtag\/js\?id=G-/, 1), html(/gtag\(\s*['"]config['"]\s*,\s*['"]G-/, 1), cookie(/^_ga$/, 0.5)]),
  rule('ua', 'Universal Analytics (retired)', 'analytics', 'https://support.google.com/analytics/answer/11583528', [asset(/google-analytics\.com\/analytics\.js|gtag\/js\?id=UA-/, 1)]),
  rule('gtm', 'Google Tag Manager', 'analytics', 'https://tagmanager.google.com', [asset(/googletagmanager\.com\/gtm\.js/, 1), html(/GTM-[A-Z0-9]{5,8}/, 0.8)]),
  rule('meta-pixel', 'Meta Pixel', 'analytics', 'https://www.facebook.com/business/tools/meta-pixel', [asset(/connect\.facebook\.net\/[\w_]+\/fbevents\.js/, 1), html(/fbq\(\s*['"]init/, 1)]),
  rule('linkedin-insight', 'LinkedIn Insight Tag', 'analytics', 'https://business.linkedin.com/marketing-solutions/insight-tag', [asset(/snap\.licdn\.com/, 1)]),
  rule('hotjar', 'Hotjar', 'analytics', 'https://www.hotjar.com', [asset(/static\.hotjar\.com/, 1)]),
  rule('clarity', 'Microsoft Clarity', 'analytics', 'https://clarity.microsoft.com', [asset(/clarity\.ms\/tag/, 1)]),
  rule('segment', 'Segment', 'analytics', 'https://segment.com', [asset(/cdn\.segment\.com|analytics\.load\(/, 1)]),
  rule('mixpanel', 'Mixpanel', 'analytics', 'https://mixpanel.com', [asset(/cdn\.mxpnl\.com|mixpanel\.init/, 1)]),
  rule('amplitude', 'Amplitude', 'analytics', 'https://amplitude.com', [asset(/cdn\.amplitude\.com|amplitude\.getInstance/, 1)]),
  rule('heap', 'Heap', 'analytics', 'https://www.heap.io', [asset(/cdn\.heapanalytics\.com|heap\.load\(/, 1)]),
  rule('posthog', 'PostHog', 'analytics', 'https://posthog.com', [asset(/[a-z]+\.i\.posthog\.com|posthog\.init\(|\/static\/array\.js/, 1), js(/posthog/, 0.5)]),
  rule('plausible', 'Plausible', 'analytics', 'https://plausible.io', [asset(/plausible\.io\/js/, 1)]),
  rule('fathom', 'Fathom', 'analytics', 'https://usefathom.com', [asset(/cdn\.usefathom\.com/, 1)]),
  rule('umami', 'Umami', 'analytics', 'https://umami.is', [asset(/umami\.(?:is|js)|cloud\.umami/, 1)]),
  rule('vercel-analytics', 'Vercel Web Analytics', 'analytics', 'https://vercel.com/analytics', [asset(/\/_vercel\/insights\/script\.js|va\.vercel-scripts\.com/, 1)], ['vercel']),
  rule('vercel-speed', 'Vercel Speed Insights', 'monitoring', 'https://vercel.com/docs/speed-insights', [asset(/\/_vercel\/speed-insights/, 1)], ['vercel']),
  rule('cf-analytics', 'Cloudflare Web Analytics', 'analytics', 'https://www.cloudflare.com/web-analytics', [asset(/static\.cloudflareinsights\.com\/beacon/, 1)]),
  rule('hubspot', 'HubSpot', 'analytics', 'https://www.hubspot.com', [asset(/js\.hs-scripts\.com|js\.hsforms\.net|js\.hs-analytics\.net/, 1)]),
  rule('optimizely', 'Optimizely', 'analytics', 'https://www.optimizely.com', [asset(/cdn\.optimizely\.com/, 1)]),
  rule('vwo', 'VWO', 'analytics', 'https://vwo.com', [asset(/visualwebsiteoptimizer\.com/, 1)]),
  rule('onetrust', 'OneTrust', 'analytics', 'https://www.onetrust.com', [asset(/cdn\.cookielaw\.org|otSDKStub/, 1)]),
  rule('cookiebot', 'Cookiebot', 'analytics', 'https://www.cookiebot.com', [asset(/consent\.cookiebot\.com/, 1)]),

  /* Support */
  rule('intercom', 'Intercom', 'support', 'https://www.intercom.com', [asset(/widget\.intercom\.io|js\.intercomcdn\.com|intercomSettings/, 1)]),
  rule('crisp', 'Crisp', 'support', 'https://crisp.chat', [asset(/client\.crisp\.chat/, 1)]),
  rule('zendesk', 'Zendesk', 'support', 'https://www.zendesk.com', [asset(/static\.zdassets\.com|zopim/, 1)]),
  rule('tawk', 'tawk.to', 'support', 'https://www.tawk.to', [asset(/embed\.tawk\.to/, 1)]),
  rule('calendly', 'Calendly', 'support', 'https://calendly.com', [asset(/assets\.calendly\.com/, 1)]),

  /* Monitoring */
  rule('sentry', 'Sentry', 'monitoring', 'https://sentry.io', [asset(/browser\.sentry-cdn\.com|js\.sentry-cdn\.com|ingest\.(?:[a-z]+\.)?sentry\.io/, 1), meta('sentry-trace', /./), js(/__SENTRY__/, 0.8)]),
  rule('datadog', 'Datadog RUM', 'monitoring', 'https://www.datadoghq.com', [asset(/datadoghq-browser-agent\.com|DD_RUM/, 1)]),
  rule('newrelic', 'New Relic', 'monitoring', 'https://newrelic.com', [asset(/js-agent\.newrelic\.com|NREUM/, 1)]),
  rule('logrocket', 'LogRocket', 'monitoring', 'https://logrocket.com', [asset(/cdn\.logrocket\.io|cdn\.lr-ingest|LogRocket\.init/, 1)]),
  rule('fullstory', 'FullStory', 'monitoring', 'https://www.fullstory.com', [asset(/edge\.fullstory\.com|fullstory\.com\/s\/fs\.js/, 1)]),

  /* Security & certificates */
  rule('recaptcha', 'reCAPTCHA', 'security', 'https://www.google.com/recaptcha', [asset(/google\.com\/recaptcha|gstatic\.com\/recaptcha/, 1)]),
  rule('hcaptcha', 'hCaptcha', 'security', 'https://www.hcaptcha.com', [asset(/hcaptcha\.com\/1\/api\.js|js\.hcaptcha\.com/, 1)]),
  rule('turnstile', 'Cloudflare Turnstile', 'security', 'https://www.cloudflare.com/products/turnstile', [asset(/challenges\.cloudflare\.com\/turnstile/, 1)]),
  rule('letsencrypt', "Let's Encrypt", 'security', 'https://letsencrypt.org', [tls('issuer', /Let's Encrypt/)]),
  rule('google-trust', 'Google Trust Services', 'security', 'https://pki.goog', [tls('issuer', /Google Trust Services/)]),
  rule('amazon-ca', 'Amazon Trust Services', 'security', 'https://www.amazontrust.com', [tls('issuer', /^Amazon/)]),
  rule('digicert', 'DigiCert', 'security', 'https://www.digicert.com', [tls('issuer', /DigiCert/)]),
  rule('sectigo', 'Sectigo', 'security', 'https://www.sectigo.com', [tls('issuer', /Sectigo|COMODO/i)]),
  rule('globalsign', 'GlobalSign', 'security', 'https://www.globalsign.com', [tls('issuer', /GlobalSign/)]),
  rule('zerossl', 'ZeroSSL', 'security', 'https://zerossl.com', [tls('issuer', /ZeroSSL/)]),

  /* Email & domain */
  rule('google-workspace', 'Google Workspace', 'email', 'https://workspace.google.com', [dns('mx', /google(?:mail)?\.com$|smtp\.google\.com$/, 1), dns('txt', /include:_spf\.google\.com/, 0.8)]),
  rule('microsoft-365', 'Microsoft 365', 'email', 'https://www.microsoft.com/microsoft-365', [dns('mx', /mail\.protection\.outlook\.com$/, 1), dns('txt', /include:spf\.protection\.outlook\.com/, 0.8)]),
  rule('zoho-mail', 'Zoho Mail', 'email', 'https://www.zoho.com/mail', [dns('mx', /zoho\.(?:com|in|eu)$/, 1)]),
  rule('proton-mail', 'Proton Mail', 'email', 'https://proton.me/mail', [dns('mx', /protonmail\.ch$/, 1)]),
  rule('sendgrid', 'SendGrid', 'email', 'https://sendgrid.com', [dns('txt', /include:sendgrid\.net/, 1)]),
  rule('mailgun', 'Mailgun', 'email', 'https://www.mailgun.com', [dns('txt', /include:mailgun\.org/, 1)]),
  rule('amazon-ses', 'Amazon SES', 'email', 'https://aws.amazon.com/ses', [dns('txt', /include:amazonses\.com/, 1)]),
  rule('search-console', 'Google Search Console', 'email', 'https://search.google.com/search-console', [dns('txt', /^google-site-verification=/, 0.7)]),
];
