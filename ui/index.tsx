import { TerminalIcon, type ServicePlugin } from '@holistic/ui';
import { Console } from './Console';

// remshel's dashboard plugin. Linked into holistic/frontend/external/remshel at install
// time and discovered by the host SPA's build-time registry. `id` MUST equal the link dir
// name and the permissions manifest's "service" field.
const plugin: ServicePlugin = {
  id: 'remshel',
  displayName: 'Remote Shell',
  icon: TerminalIcon,
  order: 30,
  Component: Console,
};

export default plugin;
