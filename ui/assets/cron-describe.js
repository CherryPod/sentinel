// @ts-check
/**
 * cron-describe — translate the COMMON cron shapes Sentinel routines use
 * into plain English. Anything unrecognised falls back to
 * "Custom schedule (<raw>)" — honesty over cleverness. NOT a cron parser.
 */

const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

/**
 * @param {string} expr
 * @returns {string}
 */
export function describeCron(expr) {
  const raw = String(expr || '').trim();
  const fallback = `Custom schedule (${raw})`;
  const fields = raw.split(/\s+/);
  if (fields.length !== 5) return fallback;

  const [minute, hour, dayOfMonth, month, dayOfWeek] = fields;
  /** @param {string} value */
  const pad = (value) => value.padStart(2, '0');

  if (/^\*\/\d+$/.test(minute) && hour === '*' && dayOfMonth === '*' && month === '*' && dayOfWeek === '*') {
    const step = Number(minute.slice(2));
    if (step <= 0) return fallback; // */0 is invalid cron — don't guess
    return step === 1 ? 'Every minute' : `Every ${step} minutes`;
  }

  if (minute === '0' && hour === '*' && dayOfMonth === '*' && month === '*' && dayOfWeek === '*') {
    return 'Every hour';
  }

  if (/^\d+$/.test(minute) && /^\d+$/.test(hour) && dayOfMonth === '*' && month === '*') {
    // Range-check before emitting English — never show "25:99" as a real time.
    if (Number(minute) > 59 || Number(hour) > 23) return fallback;
    const time = `${pad(hour)}:${pad(minute)}`;
    if (dayOfWeek === '*') return `Every day at ${time}`;
    if (/^[0-6]$/.test(dayOfWeek)) return `Every ${DAYS[Number(dayOfWeek)]} at ${time}`;
  }

  return fallback;
}

/**
 * Normalise a trigger_config into the scalar string the describers expect.
 * The routines API serialises trigger_config as a DICT
 * ({"cron": "..."} | {"seconds": N} | {"event": "..."}); the live create-form
 * hint passes the raw user-typed string. Accept both shapes.
 * @param {string|Record<string, any>|undefined|null} config
 * @param {string} [type]
 * @returns {string}
 */
function configValue(config, type) {
  if (config == null) return '';
  if (typeof config === 'string') return config;
  if (typeof config === 'object') {
    if (type === 'cron' && config.cron != null) return String(config.cron);
    if (type === 'event' && config.event != null) return String(config.event);
    if (type === 'interval') {
      if (config.seconds != null) return String(config.seconds);
      if (config.interval != null) return String(config.interval);
    }
    const v = config.cron ?? config.event ?? config.seconds ?? config.interval;
    return v != null ? String(v) : '';
  }
  return String(config);
}

/**
 * @param {{ trigger_type?: string, trigger_config?: string|Record<string, any> }} routine
 * @returns {string}
 */
export function describeTrigger(routine) {
  const config = configValue(routine.trigger_config, routine.trigger_type);

  if (routine.trigger_type === 'cron') {
    return describeCron(config);
  }

  if (routine.trigger_type === 'interval') {
    const seconds = parseInt(config, 10);
    if (!Number.isFinite(seconds) || seconds <= 0) return config ? `Custom interval (${config})` : 'Custom interval';
    if (seconds % 3600 === 0) return seconds === 3600 ? 'Every hour' : `Every ${seconds / 3600} hours`;

    const minutes = Math.max(1, Math.round(seconds / 60));
    return `Every ${minutes} minute${minutes === 1 ? '' : 's'}`;
  }

  if (routine.trigger_type === 'event') {
    return config ? `When ${config} happens` : 'On an event';
  }

  return config;
}
