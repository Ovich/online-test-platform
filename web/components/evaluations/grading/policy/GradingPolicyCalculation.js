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
import UserHelpPopper from '@/components/feedback/UserHelpPopper'
import GradualPolicyCalculationBreakdown from '@/components/evaluations/grading/policy/GradualPolicyCalculationBreakdown'
import { Typography } from '@mui/material'
import { MultipleChoiceGradingPolicyType } from '@prisma/client'
import { useEffect, useState } from 'react'
import AllOrNothingPolicyCalculationBreakdown from './AllOrNothingCalculationBreakdown'
import {
  calculateAllOrNothingPoints,
  calculateGradualCreditPoints,
} from '@/code/grading/calculation'

const gradingPolicyToLabel = {
  [MultipleChoiceGradingPolicyType.GRADUAL_CREDIT]: 'Gradual Credit',
  [MultipleChoiceGradingPolicyType.ALL_OR_NOTHING]: 'All or Nothing',
}

const extractGradualCreditData = (maxPoints, solution, answer) => {
  const correctOptions = solution.options.filter((option) => option.isCorrect)
  const incorrectOptions = solution.options.filter(
    (option) => !option.isCorrect,
  )

  const selectedCorrectOptions = answer.options.filter((answer) =>
    correctOptions.some((option) => option.id === answer.id),
  )

  const selectedIncorrectOptions = answer.options.filter((answer) =>
    incorrectOptions.some((option) => option.id === answer.id),
  )

  const threshold = solution.gradualCreditConfig.threshold
  const negativeMarking = solution.gradualCreditConfig.negativeMarking

  const { finalScore, rawScore, correctnessRatio } =
    calculateGradualCreditPoints(
      maxPoints,
      correctOptions.length,
      incorrectOptions.length,
      selectedCorrectOptions.length,
      selectedIncorrectOptions.length,
      threshold,
      negativeMarking,
    )

  return {
    totalPoints: maxPoints,
    correctOptions: correctOptions.length,
    incorrectOptions: incorrectOptions.length,
    selectedCorrectOptions: selectedCorrectOptions.length,
    selectedIncorrectOptions: selectedIncorrectOptions.length,
    threshold,
    negativeMarking,
    rawScore,
    correctnessRatio,
    finalScore,
  }
}

const extractAllOrNothingData = (maxPoints, solution, answer) => {
  const correctOptions = solution.options.filter((option) => option.isCorrect)
  const incorrectOptions = solution.options.filter(
    (option) => !option.isCorrect,
  )

  const selectedCorrectOptions = answer.options.filter((answer) =>
    correctOptions.some((option) => option.id === answer.id),
  )

  const selectedIncorrectOptions = answer.options.filter((answer) =>
    incorrectOptions.some((option) => option.id === answer.id),
  )

  const { finalScore } = calculateAllOrNothingPoints(
    maxPoints,
    correctOptions,
    answer.options,
  )

  return {
    totalPoints: maxPoints,
    correctOptions: correctOptions.length,
    incorrectOptions: incorrectOptions.length,
    selectedCorrectOptions: selectedCorrectOptions.length,
    selectedIncorrectOptions: selectedIncorrectOptions.length,
    finalScore,
  }
}

const GradingPolicyCalculation = ({
  gradingPolicy,
  maxPoints,
  solution,
  answer,
}) => {
  const [data, setData] = useState(null)

  useEffect(() => {
    switch (gradingPolicy) {
      case MultipleChoiceGradingPolicyType.GRADUAL_CREDIT: {
        setData(extractGradualCreditData(maxPoints, solution, answer))
        break
      }
      case MultipleChoiceGradingPolicyType.ALL_OR_NOTHING: {
        setData(extractAllOrNothingData(maxPoints, solution, answer))
        break
      }
      default:
        setData(null)
    }
  }, [gradingPolicy, maxPoints, solution, answer])

  return (
    data && (
      <UserHelpPopper
        label={
          <Typography variant="body2" color="textSecondary" noWrap>
            {gradingPolicyToLabel[gradingPolicy]} <b>({data.finalScore} pts)</b>
          </Typography>
        }
      >
        {(() => {
          switch (gradingPolicy) {
            case MultipleChoiceGradingPolicyType.GRADUAL_CREDIT: {
              return <GradualPolicyCalculationBreakdown {...data} />
            }
            case MultipleChoiceGradingPolicyType.ALL_OR_NOTHING: {
              return <AllOrNothingPolicyCalculationBreakdown {...data} />
            }
            // Add cases for other grading policies here
            default:
              return null
          }
        })()}
      </UserHelpPopper>
    )
  )
}

export default GradingPolicyCalculation
