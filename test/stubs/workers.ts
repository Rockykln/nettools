// Minimal stand-in for the runtime module so the worker can be imported under Node.
export class WorkerEntrypoint<E = unknown> {
  constructor(
    protected ctx: ExecutionContext,
    protected env: E,
  ) {}
}
