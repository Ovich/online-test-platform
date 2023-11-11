import {withAuthorization, withMethodHandler} from "../../../../../middleware/withAuthorization";
import {withPrisma} from "../../../../../middleware/withPrisma";
import {Role} from "@prisma/client";

const get = async (req, res, prisma) => {
  const { jamSessionId } = req.query
  const jamSession = await prisma.jamSession.findUnique({
    where: {
      id: jamSessionId,
    },
    select: {
      phase: true,
      startAt: true,
      endAt: true,
    },
  })
  res.status(200).json(jamSession)
}

export default withMethodHandler({
  GET: withAuthorization(
    withPrisma(get), [Role.PROFESSOR, Role.STUDENT]
  ),
})
