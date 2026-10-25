import type { Finding } from './engine.ts';
import type { Security, Verdict } from './verdict.ts';

export interface Step {
  phase: string;
  title: string;
  command: string;
  why: string;
}

interface Recipe { id: string; phase: string; title: string; command: string }

// Ordered by phase; the first match in a phase decides the scaffold.
const SCAFFOLDS: Recipe[] = [
  { id: 'nextjs', phase: 'Scaffold', title: 'Start a Next.js app', command: 'npx create-next-app@latest my-site --ts --app' },
  { id: 'nuxt', phase: 'Scaffold', title: 'Start a Nuxt app', command: 'npm create nuxt@latest my-site' },
  { id: 'remix', phase: 'Scaffold', title: 'Start a React Router app', command: 'npx create-react-router@latest my-site' },
  { id: 'sveltekit', phase: 'Scaffold', title: 'Start a SvelteKit app', command: 'npx sv create my-site' },
  { id: 'astro', phase: 'Scaffold', title: 'Start an Astro site', command: 'npm create astro@latest my-site' },
  { id: 'gatsby', phase: 'Scaffold', title: 'Start a Gatsby site (or Astro for new work)', command: 'npm init gatsby' },
  { id: 'docusaurus', phase: 'Scaffold', title: 'Start a Docusaurus site', command: 'npx create-docusaurus@latest my-docs classic' },
  { id: 'vitepress', phase: 'Scaffold', title: 'Start a VitePress site', command: 'npx vitepress init' },
  { id: 'angular', phase: 'Scaffold', title: 'Start an Angular app', command: 'npx @angular/cli new my-site' },
  { id: 'qwik', phase: 'Scaffold', title: 'Start a Qwik app', command: 'npm create qwik@latest' },
  { id: 'solid', phase: 'Scaffold', title: 'Start a SolidStart app', command: 'npm init solid@latest' },
  { id: 'vue', phase: 'Scaffold', title: 'Start a Vue app with Vite', command: 'npm create vue@latest' },
  { id: 'react', phase: 'Scaffold', title: 'Start a React app with Vite', command: 'npm create vite@latest my-site -- --template react-ts' },
  { id: 'shopify', phase: 'Scaffold', title: 'Start a Shopify theme (or a Hydrogen storefront)', command: 'shopify theme init' },
  { id: 'wordpress', phase: 'Scaffold', title: 'Run WordPress locally', command: 'npx @wordpress/env start' },
  { id: 'hugo', phase: 'Scaffold', title: 'Start a Hugo site', command: 'hugo new site my-site' },
  { id: 'jekyll', phase: 'Scaffold', title: 'Start a Jekyll site', command: 'jekyll new my-site' },
  { id: 'eleventy', phase: 'Scaffold', title: 'Start an Eleventy site', command: 'npm i -D @11ty/eleventy' },
  { id: 'django', phase: 'Scaffold', title: 'Start a Django project', command: 'django-admin startproject mysite' },
  { id: 'rails', phase: 'Scaffold', title: 'Start a Rails app', command: 'rails new my-site' },
  { id: 'laravel', phase: 'Scaffold', title: 'Start a Laravel app', command: 'composer create-project laravel/laravel my-site' },
  { id: 'webflow', phase: 'Scaffold', title: 'Built in Webflow: rebuild in code with Astro for full ownership', command: 'npm create astro@latest my-site' },
  { id: 'framer', phase: 'Scaffold', title: 'Built in Framer: rebuild in code with Next.js + Motion', command: 'npx create-next-app@latest my-site --ts' },
  { id: 'wix', phase: 'Scaffold', title: 'Built in Wix: rebuild in code with Astro', command: 'npm create astro@latest my-site' },
  { id: 'squarespace', phase: 'Scaffold', title: 'Built in Squarespace: rebuild in code with Astro', command: 'npm create astro@latest my-site' },
];

const ADDONS: Recipe[] = [
  { id: 'tailwind', phase: 'Styling', title: 'Add Tailwind CSS', command: 'npm i -D tailwindcss @tailwindcss/vite' },
  { id: 'bootstrap', phase: 'Styling', title: 'Add Bootstrap', command: 'npm i bootstrap' },
  { id: 'mui', phase: 'Styling', title: 'Add Material UI', command: 'npm i @mui/material @emotion/react @emotion/styled' },
  { id: 'chakra', phase: 'Styling', title: 'Add Chakra UI', command: 'npm i @chakra-ui/react' },
  { id: 'radix', phase: 'Styling', title: 'Add Radix primitives (shadcn/ui wraps them)', command: 'npx shadcn@latest init' },
  { id: 'styled-components', phase: 'Styling', title: 'Add styled-components', command: 'npm i styled-components' },
  { id: 'gsap', phase: 'Motion & graphics', title: 'Add GSAP for scroll and timeline animation', command: 'npm i gsap' },
  { id: 'framer-motion', phase: 'Motion & graphics', title: 'Add Motion for component animation', command: 'npm i motion' },
  { id: 'threejs', phase: 'Motion & graphics', title: 'Add Three.js for WebGL scenes', command: 'npm i three' },
  { id: 'lottie', phase: 'Motion & graphics', title: 'Add Lottie for vector animation', command: 'npm i lottie-web' },
  { id: 'supabase', phase: 'Data & content', title: 'Connect Supabase (Postgres, auth, storage)', command: 'npm i @supabase/supabase-js' },
  { id: 'firebase', phase: 'Data & content', title: 'Connect Firebase', command: 'npm i firebase' },
  { id: 'apollo', phase: 'Data & content', title: 'Add a GraphQL client', command: 'npm i @apollo/client graphql' },
  { id: 'contentful', phase: 'Data & content', title: 'Pull content from Contentful', command: 'npm i contentful' },
  { id: 'sanity', phase: 'Data & content', title: 'Pull content from Sanity', command: 'npm create sanity@latest' },
  { id: 'prismic', phase: 'Data & content', title: 'Pull content from Prismic', command: 'npx @slicemachine/init@latest' },
  { id: 'storyblok', phase: 'Data & content', title: 'Pull content from Storyblok', command: 'npm i @storyblok/js' },
  { id: 'algolia', phase: 'Data & content', title: 'Add Algolia search', command: 'npm i algoliasearch' },
  { id: 'mapbox', phase: 'Data & content', title: 'Add Mapbox maps', command: 'npm i mapbox-gl' },
  { id: 'clerk', phase: 'Accounts', title: 'Add Clerk sign-in', command: 'npm i @clerk/nextjs' },
  { id: 'auth0', phase: 'Accounts', title: 'Add Auth0 sign-in', command: 'npm i @auth0/auth0-spa-js' },
  { id: 'nextauth', phase: 'Accounts', title: 'Add Auth.js sign-in', command: 'npm i next-auth' },
  { id: 'stripe', phase: 'Payments', title: 'Take payments with Stripe', command: 'npm i @stripe/stripe-js stripe' },
  { id: 'paypal', phase: 'Payments', title: 'Take payments with PayPal', command: 'npm i @paypal/paypal-js' },
  { id: 'razorpay', phase: 'Payments', title: 'Take payments with Razorpay', command: 'npm i razorpay' },
  { id: 'paddle', phase: 'Payments', title: 'Sell with Paddle', command: 'npm i @paddle/paddle-js' },
  { id: 'vercel', phase: 'Hosting', title: 'Deploy on Vercel', command: 'npx vercel' },
  { id: 'netlify', phase: 'Hosting', title: 'Deploy on Netlify', command: 'npx netlify deploy --prod' },
  { id: 'cloudflare-pages', phase: 'Hosting', title: 'Deploy on Cloudflare Pages', command: 'npx wrangler pages deploy dist' },
  { id: 'firebase-hosting', phase: 'Hosting', title: 'Deploy on Firebase Hosting', command: 'npx firebase-tools deploy' },
  { id: 'github-pages', phase: 'Hosting', title: 'Publish on GitHub Pages', command: 'Settings → Pages → Deploy from GitHub Actions' },
  { id: 'fly', phase: 'Hosting', title: 'Deploy on Fly.io', command: 'fly launch' },
  { id: 'render', phase: 'Hosting', title: 'Deploy on Render', command: 'Connect the repo at dashboard.render.com' },
  { id: 'railway', phase: 'Hosting', title: 'Deploy on Railway', command: 'npx @railway/cli up' },
  { id: 'cloudfront', phase: 'Hosting', title: 'Serve through CloudFront in front of S3', command: 'aws s3 sync dist s3://my-bucket && aws cloudfront create-invalidation --distribution-id ID --paths "/*"' },
  { id: 'cloudflare', phase: 'Hosting', title: 'Put Cloudflare in front for CDN, TLS and bot protection', command: 'Add the domain at dash.cloudflare.com and switch nameservers' },
  { id: 'plausible', phase: 'Measure', title: 'Add Plausible analytics', command: '<script defer data-domain="example.com" src="https://plausible.io/js/script.js"></script>' },
  { id: 'posthog', phase: 'Measure', title: 'Add PostHog product analytics', command: 'npm i posthog-js' },
  { id: 'ga4', phase: 'Measure', title: 'Add Google Analytics 4', command: 'npm i @next/third-parties  # or the gtag.js snippet' },
  { id: 'vercel-analytics', phase: 'Measure', title: 'Add Vercel Web Analytics', command: 'npm i @vercel/analytics' },
  { id: 'sentry', phase: 'Measure', title: 'Add Sentry error monitoring', command: 'npx @sentry/wizard@latest -i nextjs' },
];

export function protocol(findings: Finding[], verdict: Verdict, security: Security): Step[] {
  const solid = new Map(findings.filter((f) => f.confidence === 'confirmed' || f.confidence === 'probable' || f.confidence === 'implied').map((f) => [f.id, f]));
  const because = (f: Finding) =>
    f.exhibits.length ? `${f.name}, exhibit${f.exhibits.length > 1 ? 's' : ''} ${f.exhibits.slice(0, 3).join(', ')}` : `${f.name}, implied by ${f.impliedBy.join(', ')}`;

  const steps: Step[] = [];
  const scaffold = SCAFFOLDS.find((r) => solid.has(r.id));
  steps.push(scaffold
    ? { phase: 'Scaffold', title: scaffold.title, command: scaffold.command, why: `${because(solid.get(scaffold.id)!)}. Rendering: ${verdict.mode}.` }
    : { phase: 'Scaffold', title: 'Start from plain HTML with Vite', command: 'npm create vite@latest my-site -- --template vanilla-ts', why: `No front-end framework was identified. Rendering: ${verdict.mode}.` });

  for (const r of ADDONS) {
    const f = solid.get(r.id);
    if (f) steps.push({ phase: r.phase, title: r.title, command: r.command, why: because(f) });
  }

  const missing = security.rows.filter((r) => !r.pass && r.id !== 'tls' && r.id !== 'https');
  if (missing.length) {
    steps.push({
      phase: 'Harden',
      title: `Send the ${missing.length} security header${missing.length > 1 ? 's' : ''} this site skips`,
      command: missing.map((r) => r.advice).join('\n'),
      why: `Missing on the subject: ${missing.map((r) => r.label).join(', ')}.`,
    });
  }
  return steps;
}
