import { StepLabel, StepContent, Typography, Stack, Box, Alert } from '@mui/material'
import MinutesSelector from '../in-progress/MinutesSelector'
import JamSessionCountDown from './JamSessionCountDown'
const StepInProgress = ({ jamSession, onDurationChange, onJamSessionEnd }) => {
  return (
    <>
      <StepLabel>In progress</StepLabel>
      <StepContent>
        {jamSession.startAt && jamSession.endAt ? (
          <DurationManager
            jamSession={jamSession}
            onChange={onDurationChange}
            onJamSessionEnd={onJamSessionEnd}
          />
        ) : (
          <Stack
            spacing={4}
            direction="row"
            alignItems="center"
            justifyContent="center"
          >
            <Box>
              <Typography variant="h6">
                The exam session is in progress.
              </Typography>
              <Typography variant="body1">
                To end the jam session click the button below.
              </Typography>
            </Box>
          </Stack>
        )}
      </StepContent>
    </>
  )
}

const DurationManager = ({ jamSession, onChange, onJamSessionEnd }) => {
  return (
    <Stack pt={4} pb={4} spacing={2}>
      <Stack
        spacing={4}
        direction="row"
        alignItems="center"
        justifyContent="space-between"
      >
        <MinutesSelector
          label={'Reduce by'}
          color="primary"
          onClick={async (minutes) => {
            // remove minutes to endAt
            let newEndAt = new Date(jamSession.endAt)
            newEndAt.setMinutes(newEndAt.getMinutes() - minutes)
            newEndAt = new Date(newEndAt).toISOString()
            onChange(newEndAt)
          }}
        />
        <Typography variant="body1">
          {`Started at ${new Date(jamSession.startAt).toLocaleTimeString()}`}
        </Typography>
        <JamSessionCountDown
          startDate={jamSession.startAt}
          endDate={jamSession.endAt}
          onFinish={onJamSessionEnd}
        />
        <Typography variant="body1">
          {`Ends at ${new Date(jamSession.endAt).toLocaleTimeString()}`}
        </Typography>
        <MinutesSelector
          label={'Extend for'}
          color="info"
          onClick={async (minutes) => {
            // add minutes to endAt
            let newEndAt = new Date(jamSession.endAt)
            newEndAt.setMinutes(newEndAt.getMinutes() + minutes)
            newEndAt = new Date(newEndAt).toISOString()
            onChange(newEndAt)
          }}
        />
      </Stack>
      <Alert severity={'info'}>
        <Typography variant="body1">
          The jam session will <b>not end automatically</b> after the contdown.
        </Typography>
      </Alert>
    </Stack>
  )
}

export default StepInProgress
