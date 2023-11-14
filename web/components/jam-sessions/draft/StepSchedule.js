import useSWR from 'swr'
import { useState, useEffect } from 'react'
import {
  Stack,
  Typography,
  FormGroup,
  FormControlLabel,
  Switch,
  Alert,
  AlertTitle,
} from '@mui/material'
import DurationPicker from '@/components/input/DurationPicker'
import StudentList from './StudentList'

import { fetcher } from '@/code/utils'
import Loading from '@/components/feedback/Loading'

const STUDENTS_ACTIVE_PULL_INTERVAL = 1000;

const StepSchedule = ({ groupScope, jamSession, onChange }) => {

  const {
    data: students,
    error: errorStudents,
  } = useSWR(
      `/api/${groupScope}/jam-sessions/${jamSession.id}/students`,
      groupScope && jamSession?.id ? fetcher : null,
      { refreshInterval: STUDENTS_ACTIVE_PULL_INTERVAL}
      )


  const [useDuration, setUseDuration] = useState(false)
  const [duration, setDuration] = useState({
    hours: 0,
    minutes: 0,
  })

  useEffect(() => {
    onChange(useDuration ? duration : { hours: 0, minutes: 0 })
  }, [duration, useDuration, onChange])

  useEffect(() => {
    if (jamSession) {
      if (jamSession.durationHours > 0 || jamSession.durationMins > 0) {
        // hours and minutes between startAt and endAt
        setUseDuration(true)
        setDuration({
          hours: jamSession.durationHours,
          minutes: jamSession.durationMins,
        })
      }
    }
  }, [jamSession])

  return (
    <Stack spacing={2}>
      <Typography variant="h6">Schedule</Typography>
      <FormGroup>
        <FormControlLabel
          control={
            <Switch
              checked={useDuration}
              onChange={(e) => {
                setUseDuration(e.target.checked)
                if (!e.target.checked) {
                  setDuration({
                    hours: 0,
                    minutes: 0,
                  })
                }
              }}
            />
          }
          label="Set jam session duration"
        />
      </FormGroup>
      {useDuration && (
        <>
          <Alert severity="warning">
            <AlertTitle>Warning</AlertTitle>
            <Typography variant="body1">
              The jam session will not end automatically. You will have to end it manually in the in-progress phase.
            </Typography>
            <Typography variant="body1">
              The sole purpose of this feature is to give students an idea of the time they have to complete the jam session.
            </Typography>
          </Alert>
          <DurationPicker
            value={duration}
            onChange={(value) => {
                setDuration(value)
            }}
          />
        </>

      )}
      { jamSession.id && (
        <Loading loading={!students} errors={[errorStudents]}>
         <StudentList
            title={`Registered students (${students?.students.length})`}
            students={students?.students}
         />
         </Loading>
      )}

      </Stack>
  )
}


export default StepSchedule
