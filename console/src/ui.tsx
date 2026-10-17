// SPDX-License-Identifier: BUSL-1.1
import type {ReactNode} from 'react';
import {Radio} from 'lucide-react';

export function Loading() {
  return <div className="loading-row" role="status"><span className="spinner" aria-hidden="true"/>Loading…</div>;
}

export function Empty({title, text, icon, children}: {title: string; text: string; icon?: ReactNode; children?: ReactNode}) {
  return <div className="empty"><span className="empty-icon">{icon ?? <Radio size={22}/>}</span><h3>{title}</h3><p>{text}</p>{children && <div className="empty-actions">{children}</div>}</div>;
}

// One plain sentence up front; the precise caveats stay one click away.
export function About({lead, children}: {lead: ReactNode; children: ReactNode}) {
  return <div className="about"><p className="muted">{lead}</p><details><summary>About this evidence</summary><div className="about-body">{children}</div></details></div>;
}
