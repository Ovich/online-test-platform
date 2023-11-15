import { useRouter } from 'next/router'
import useSWR from 'swr'
import { Autocomplete, Stack, TextField, Typography } from '@mui/material'
import { useEffect, useState } from 'react'
import { Role } from '@prisma/client'

import { fetcher } from '@/code/utils'

import BackButton from '@/components/layout/BackButton'
import LayoutMain from '@/components/layout/LayoutMain'
import Authorisation from '@/components/security/Authorisation'
import Loading from '@/components/feedback/Loading'

import EvaluationAnalytics from '../analytics/EvaluationAnalytics'

const PageAnalytics = () => {
  const router = useRouter()
  const { groupScope, evaluationId } = router.query

    console.log("PageAnalytics")

  const { data: evaluations, error: errorEvaluations } = useSWR(
    `/api/${groupScope}/evaluations`,
      groupScope && evaluationId ? fetcher : null
  )

  const { data: evaluation, error: errorEvaluation } = useSWR(
    `/api/${groupScope}/evaluations/${evaluationId}`,
      groupScope && evaluationId ? fetcher : null
  )

  const { data: evaluationToQuestions, error: errorQuestions } = useSWR(
    `/api/${groupScope}/evaluations/${evaluationId}/questions?withGradings=true`,
      groupScope && evaluationId ? fetcher : null,
    { refreshInterval: 1000 }
  )

  const [value, setValue] = useState(null)
  const [inputValue, setInputValue] = useState('')

  useEffect(() => {
    if (evaluation) {
      setValue(evaluation)
      setInputValue(evaluation.label)
    }
  }, [evaluation])

  return (
    <Authorisation allowRoles={[Role.PROFESSOR]}>
      <Loading
        error={[errorEvaluations, errorEvaluation, errorQuestions]}
        loading={!evaluation || !evaluations || !evaluationToQuestions}
      >
        <LayoutMain
            header={
              <Stack direction="row" alignItems="center">
                <BackButton backUrl={`/${groupScope}/evaluations`} />
                { evaluation?.id && (
                  <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
                    {evaluation.label}
                  </Typography>
                )}
              </Stack>
            }
            padding={2}
            spacing={2}
          >
          {evaluation && evaluations && evaluationToQuestions && (
            <Stack alignItems="center" spacing={2} padding={2}>
              <Autocomplete
                id="chose-evaluation"
                options={evaluations}
                getOptionLabel={(option) => option.label}
                sx={{ width: '70%' }}
                renderInput={(params) => (
                  <TextField
                    {...params}
                    label="evaluation"
                    variant="outlined"
                  />
                )}
                value={value}
                onChange={async (event, newValue) => {
                  if (newValue && newValue.id) {
                    await router.push(`/${groupScope}/evaluations/${newValue.id}/analytics`)
                  }
                }}
                inputValue={inputValue}
                onInputChange={(event, newInputValue) => {
                  setInputValue(newInputValue)
                }}
                isOptionEqualToValue={(option, value) => option.id === value.id}
              />
              <EvaluationAnalytics
                evaluationToQuestions={evaluationToQuestions}
              />
            </Stack>
          )}
        </LayoutMain>
      </Loading>
    </Authorisation>
  )
}

export default PageAnalytics
