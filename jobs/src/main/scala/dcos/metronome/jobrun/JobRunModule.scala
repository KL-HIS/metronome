package dcos.metronome.jobrun

import akka.actor.{ ActorContext, ActorSystem, Props }
import dcos.metronome.behavior.Behavior
import dcos.metronome.jobrun.impl.{ JobRunExecutorActor, JobRunPersistenceActor, JobRunServiceActor, JobRunServiceDelegate }
import dcos.metronome.model.{ JobResult, JobRun, JobRunId }
import dcos.metronome.repository.Repository
import dcos.metronome.utils.time.Clock
import mesosphere.marathon.MarathonSchedulerDriverHolder
import mesosphere.marathon.core.launchqueue.LaunchQueue

import scala.concurrent.Promise

class JobRunModule(
    config:           JobRunConfig,
    actorSystem:      ActorSystem,
    clock:            Clock,
    jobRunRepository: Repository[JobRunId, JobRun],
    launchQueue:      LaunchQueue,
    driverHolder:     MarathonSchedulerDriverHolder,
    behavior:         Behavior
) {

  import com.softwaremill.macwire._

  private[this] def executorFactory(jobRun: JobRun, promise: Promise[JobResult]): Props = {
    val persistenceActorFactory = (id: JobRunId, context: ActorContext) =>
      context.actorOf(JobRunPersistenceActor.props(id, jobRunRepository, behavior))
    JobRunExecutorActor.props(jobRun, promise, persistenceActorFactory, launchQueue, driverHolder, clock, behavior)
  }

  //TODO: Start when we get elected
  private[this] val jobRunServiceActor = actorSystem.actorOf(
    JobRunServiceActor.props(clock, executorFactory, jobRunRepository, behavior)
  )

  def jobRunService: JobRunService = behavior(wire[JobRunServiceDelegate])
}