import clsx from 'clsx';
import Link from '@docusaurus/Link';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

const DetectionLayers = [
  {
    title: 'Prevention',
    description: (
      <>
        Policy blocks unapproved action sources before they execute.
        Tag rewrite is irrelevant if you enforce source and SHA pinning.
      </>
    ),
  },
  {
    title: 'Content Detection',
    description: (
      <>
        Recursive secret scanning catches credential harvesting in build output,
        even through layers of base64 encoding. The build is blocked.
      </>
    ),
  },
  {
    title: 'Behavioral Detection',
    description: (
      <>
        Syscall tracing + OPA policy catches covert exfiltration that never hits stdout.
        The attacker writes creds to files — cilock catches the filesystem access pattern.
      </>
    ),
  },
];

function Layer({title, description}) {
  return (
    <div className={clsx('col col--4')}>
      <div className={styles.layerCard}>
        <Heading as="h3" className={styles.layerTitle}>{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function CilockShowcase() {
  return (
    <section className={styles.showcase}>
      <div className="container">
        <div className={styles.header}>
          <Heading as="h2" className={styles.sectionTitle}>
            cilock
          </Heading>
          <p className={styles.sectionLead}>
            Protecting against malicious GitHub Actions.
          </p>
          <p className={styles.sectionSubtitle}>
            An attacker hijacked a popular GitHub Action. Every pipeline using it started
            exfiltrating secrets — SSH keys, cloud credentials, Kubernetes tokens, all to an
            attacker-controlled domain. The industry response was "pin your SHAs."
            That's one lock on a building that needs three.
          </p>
        </div>

        <div className="row">
          {DetectionLayers.map((props, idx) => (
            <Layer key={idx} {...props} />
          ))}
        </div>

        <div className={styles.attestationNote}>
          <p>
            Every attestation is cryptographically signed and timestamped.
            Not logging — <strong>tamper-evident proof</strong> of what ran and whether it met policy.
          </p>
          <p className={styles.tagline}>
            Pinning is a lock. Attestation is a security camera, a receipt, and a notary.
          </p>
        </div>

        <div className={styles.links}>
          <Link
            className="button button--primary button--md"
            href="https://github.com/aflock-ai/cilock-action">
            GitHub
          </Link>
          <Link
            className="button button--outline button--primary button--md"
            href="https://testifysec.com/blog/cilock-action-supply-chain-attacks">
            Trivy Attack Analysis
          </Link>
          <Link
            className="button button--outline button--primary button--md"
            href="https://testifysec.com/blog/cilock-litellm-supply-chain-attack">
            LiteLLM Attack Analysis
          </Link>
          <Link
            className="button button--outline button--primary button--md"
            to="/docs/docs/ecosystem/cilock-action">
            Docs
          </Link>
        </div>
      </div>
    </section>
  );
}
