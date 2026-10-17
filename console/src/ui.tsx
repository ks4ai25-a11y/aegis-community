import type {ReactNode} from 'react';
import {Radio} from 'lucide-react';

export function Loading() {
  return <div className="loading-row" role="status"><span className="spinner" aria-hidden="true"/>Loading…</div>;
}

export function Empty({title, text, icon, children}: {title: string; text: string; icon?: ReactNode; children?: ReactNode}) {
  return <div className="empty"><span className="empty-icon">{icon ?? <Radio size={22}/>}</span><h3>{title}</h3><p>{text}</p>{children && <div className="empty-actions">{children}</div>}</div>;
}
