/**
 * Copyright 2022-2024 HEIG-VD
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import {
  EvaluationPhase,
  Role,
  UserOnEvaluatioAccessMode,
} from '@prisma/client'
import { withPrisma } from '@/middleware/withPrisma'
import {
  withAuthorization,
  withGroupScope,
  withMethodHandler,
} from '@/middleware/withAuthorization'

const get = async (req, res, prisma) => {
  const { evaluationId } = req.query
  const evaluation = await prisma.evaluation.findUnique({
    where: {
      id: evaluationId,
    },
  })

  res.status(200).json(evaluation)
}

const patch = async (req, res, prisma) => {
  const { evaluationId } = req.query

  const currentEvaluation = await prisma.evaluation.findUnique({
    where: {
      id: evaluationId,
    },
    select: {
      phase: true,
      startAt: true,
      durationHours: true,
      durationMins: true,
      accessMode: true,
    },
  })

  if (!currentEvaluation) {
    res.status(404).json({ message: 'evaluation not found' })
    return
  }

  const {
    phase: nextPhase,
    label,
    conditions,
    duration,
    endAt,
    status,
    showSolutionsWhenFinished,
    accessMode,
    accessList,
  } = req.body

  let data = {}

  if (nextPhase) {
    data.phase = nextPhase
    if (nextPhase === EvaluationPhase.IN_PROGRESS) {
      // handle start and end time
      let durationHours = currentEvaluation.durationHours
      let durationMins = currentEvaluation.durationMins
      if (durationHours > 0 || durationMins > 0) {
        data.startAt = new Date()
        data.endAt = new Date(
          Date.now() + durationHours * 3600000 + durationMins * 60000,
        )
      } else {
        data.startAt = null
        data.endAt = null
      }
    }
  }

  if (label) {
    data.label = label
  }

  if (conditions) {
    data.conditions = conditions
  }

  if (status) {
    data.status = status
  }

  if (duration) {
    data.durationHours = duration.hours
    data.durationMins = duration.minutes
  }

  if (endAt) {
    let startAt = new Date(currentEvaluation.startAt)
    let newEndAt = new Date(endAt)
    if (newEndAt < startAt) {
      res.status(400).json({ message: 'End time must be after start time' })
      return
    }
    data.endAt = endAt
  }

  if (showSolutionsWhenFinished !== undefined) {
    data.showSolutionsWhenFinished = showSolutionsWhenFinished
  }

  if (accessMode) {
    data.accessMode = accessMode
  }

  if (accessList) {
    data.accessList = accessList
  }

  let evaluationAfterUpdate = undefined
  await prisma.$transaction(async (prisma) => {
    evaluationAfterUpdate = await prisma.evaluation.update({
      where: {
        id: evaluationId,
      },
      data: data,
    })

    if (
      currentEvaluation.accessMode ===
      UserOnEvaluatioAccessMode.LINK_AND_ACCESS_LIST
    ) {
      // remove eventual denied students
      await prisma.userOnEvaluationDeniedAccessAttempt.deleteMany({
        where: {
          evaluationId: evaluationId,
          userEmail: {
            in: accessList || [],
          },
        },
      })
    }
  })

  res.status(200).json(evaluationAfterUpdate)
}

const del = async (req, res, prisma) => {
  const { groupScope, evaluationId } = req.query

  /*
        get all the questions related to this evaluation
        It is not possible to cascade delete the questions because we passed bv and an intermediate relation
     */
  const jstqs = await prisma.evaluationToQuestion.findMany({
    where: {
      evaluationId: evaluationId,
    },
  })

  const questionIds = jstqs.map((jstq) => jstq.questionId)

  await prisma.$transaction(async (prisma) => {
    // delete all the questions related to this evaluation
    await prisma.question.deleteMany({
      where: {
        id: {
          in: questionIds,
        },
        group: {
          scope: groupScope,
        },
      },
    })
    await prisma.evaluation.delete({
      where: {
        id: evaluationId,
      },
    })
  })

  res.status(200).json({ message: 'evaluation deleted' })
}

export default withGroupScope(withMethodHandler({
  GET: withAuthorization(withPrisma(get), [Role.PROFESSOR]),
  PATCH: withAuthorization(withPrisma(patch), [Role.PROFESSOR]),
  DELETE: withAuthorization(withPrisma(del), [Role.PROFESSOR]),
}))
