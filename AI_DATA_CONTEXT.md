# AI 项目数据上下文 (AI Data Context)

> 本文件由 `scripts/generate_ai_context.js` 自动生成。
> **给 AI 的说明**: 本文件包含 HTML 自定义标签的中文含义以及核心游戏数据。当阅读前端 HTML 源码时，请参考此表将 `<tag>` 映射为实际文本。

## 1. 术语与 HTML 标签映射 (Terms Mapping)

前端 HTML 中的自定义标签（如 `<procedure>`）对应的实际中文含义：

| HTML 标签 (en) | 中文含义 (cn) | 替换内容 (replace) | 备注 |
| --- | --- | --- | --- |
| `<acting>` | (复合/分段) | `true` |  |
| `<actingStage>` | 出牌阶段 | - |  |
| `<actingStageProcess>` | (复合/分段) | - |  |
| `<actionType>` | 对/与作用域 | - | 分段: <directedMark>:对, <reciprocalMark>:与 |
| `<activate>` | 发动作用域 | - | 分段: <directedMark>:对, <passive>:被, <activateBody>:发动, <activater>:发动者, <activateTarget>:目标·发动, <activatedSkill>:被发动技能 |
| `<advance>` | 进行 | - |  |
| `<affect>` | 生效作用域 | - | 分段: <affectEnd>:生效, <affectRole>:来源, <affectedRole>:目标·生效, <effect>:效果·生效 |
| `<afterActingStageFinish>` | 出牌阶段结束后 | - |  |
| `<afterAffect>` | 生效后 | - |  |
| `<afterBack>` | 背置后作用域 | - | 分段: <backBody>:背置, <afterEnd>:后 |
| `<afterBacked>` | 被背置后作用域 | - | 分段: <passive>:被, <backBody>:背置, <afterEnd>:后 |
| `<afterComparison>` | 拼点后 | - |  |
| `<afterConcludingStageFinish>` | 结束阶段结束后 | - |  |
| `<afterCure>` | 造成治疗后作用域 | - | 分段: <dealtBody>:造成, <cureEnd>:治疗, <afterEnd>:后 |
| `<afterCured>` | 受到治疗后作用域 | - | 分段: <takeBody>:受到, <cureEnd>:治疗, <afterEnd>:后 |
| `<afterDamage>` | 造成伤害后作用域 | - | 分段: <dealtBody>:造成, <damageEnd>:伤害, <afterEnd>:后 |
| `<afterDamaged>` | 受到伤害后作用域 | - | 分段: <takeBody>:受到, <damageEnd>:伤害, <afterEnd>:后 |
| `<afterDealingStageFinish>` | 判定阶段结束后 | - |  |
| `<afterDie>` | 死亡后 | - |  |
| `<afterDiscard>` | 弃置后作用域 | - | 分段: <discardBody>:弃置, <afterEnd>:后 |
| `<afterDiscarded>` | 被弃置后作用域 | - | 分段: <passive>:被, <discardBody>:弃置, <afterEnd>:后 |
| `<afterDraw>` | 摸牌后 | - |  |
| `<afterFace>` | 向置后作用域 | - | 分段: <faceBody>:向置, <afterEnd>:后 |
| `<afterFaced>` | 被向置后作用域 | - | 分段: <passive>:被, <faceBody>:向置, <afterEnd>:后 |
| `<afterGettingStageFinish>` | 摸牌阶段结束后 | - |  |
| `<afterLoss>` | 流失后作用域 | - | 分段: <lossBody>:流失, <afterEnd>:后 |
| `<afterOffset>` | 抵消后 | - |  |
| `<afterPlace>` | 置于后作用域 | - | 分段: <patientMark>:将, <placeBody>:置于, <afterEnd>:后 |
| `<afterPlaced>` | 被置于后作用域 | - | 分段: <passive>:被, <placeBody>:置于, <afterEnd>:后 |
| `<afterPlay>` | 打出后作用域 | - | 分段: <playBody>:打出, <afterEnd>:后 |
| `<afterPlayed>` | 被打出后作用域 | - | 分段: <passive>:被, <playBody>:打出, <afterEnd>:后 |
| `<afterPreparingStageFinish>` | 准备阶段结束后 | - |  |
| `<afterRecover>` | 回复后作用域 | - | 分段: <recoverBody>:回复, <afterEnd>:后 |
| `<afterRoundFinish>` | 轮结束后 | - |  |
| `<afterShow>` | 展示后作用域 | - | 分段: <showBody>:展示, <afterEnd>:后 |
| `<afterShown>` | 被展示后作用域 | - | 分段: <passive>:被, <showBody>:展示, <afterEnd>:后 |
| `<afterThrowingStageFinish>` | 弃牌阶段结束后 | - |  |
| `<afterTurnFinish>` | 回合结束后 | - |  |
| `<afterUse>` | 使用后作用域 | - | 分段: <useBody>:使用, <afterEnd>:后 |
| `<afterUsed>` | 被使用后作用域 | - | 分段: <passive>:被, <useBody>:使用, <afterEnd>:后 |
| `<against>` | (复合/分段) | - |  |
| `<anyNumber>` | 任意 | - |  |
| `<anytime>` | 任何时候 | - |  |
| `<apart>` | (复合/分段) | - |  |
| `<apartOrTogether>` | 分合 | - |  |
| `<append>` | 追加作用域 | - | 分段: <passive>:被, <appendBody>:追加, <appender>:追加者, <initialTarget>:原目标, <appendTarget>:目标·追加 |
| `<area>` | 区域 | - |  |
| `<ask>` | 询问 | - |  |
| `<attribute>` | 属性 | - |  |
| `<back>` | 背置作用域 | - | 分段: <passive>:被, <backBody>:背置, <backBody1>:背, <backRole>:背置者, <backedCard>:被背置牌 |
| `<baseCard>` | 基础牌 | - |  |
| `<basicCard>` | 基本牌 | - |  |
| `<beforeActingStageStart>` | 出牌阶段开始前 | - |  |
| `<beforeAffect>` | 生效前 | - |  |
| `<beforeBack>` | 背置前作用域 | - | 分段: <backBody>:背置, <beforeEnd>:前 |
| `<beforeBacked>` | 被背置前作用域 | - | 分段: <passive>:被, <backBody>:背置, <beforeEnd>:前 |
| `<beforeComparison>` | 拼点前 | - |  |
| `<beforeConcludingStageStart>` | 结束阶段开始前 | - |  |
| `<beforeCure>` | 造成治疗前作用域 | - | 分段: <dealtBody>:造成, <cureEnd>:治疗, <beforeEnd>:前 |
| `<beforeCured>` | 受到治疗前作用域 | - | 分段: <takeBody>:受到, <cureEnd>:治疗, <beforeEnd>:前 |
| `<beforeDamage>` | 造成伤害前作用域 | - | 分段: <dealtBody>:造成, <damageEnd>:伤害, <beforeEnd>:前 |
| `<beforeDamaged>` | 受到伤害前作用域 | - | 分段: <takeBody>:受到, <damageEnd>:伤害, <beforeEnd>:前 |
| `<beforeDealingStageStart>` | 判定阶段开始前 | - |  |
| `<beforeDie>` | 死亡前 | - |  |
| `<beforeDiscard>` | 弃置前作用域 | - | 分段: <discardBody>:弃置, <beforeEnd>:前 |
| `<beforeDiscarded>` | 被弃置前作用域 | - | 分段: <passive>:被, <discardBody>:弃置, <beforeEnd>:前 |
| `<beforeDraw>` | 摸牌前 | - |  |
| `<beforeFace>` | 向置前作用域 | - | 分段: <faceBody>:向置, <beforeEnd>:前 |
| `<beforeFaced>` | 被向置前作用域 | - | 分段: <passive>:被, <faceBody>:向置, <beforeEnd>:前 |
| `<beforeGettingStageStart>` | 摸牌阶段开始前 | - |  |
| `<beforeLoss>` | 流失前作用域 | - | 分段: <lossBody>:流失, <beforeEnd>:前 |
| `<beforeOffset>` | 抵消前 | - |  |
| `<beforePlace>` | 置于前作用域 | - | 分段: <patientMark>:将, <placeBody>:置于, <beforeEnd>:前 |
| `<beforePlaced>` | 被置于前作用域 | - | 分段: <passive>:被, <placeBody>:置于, <beforeEnd>:前 |
| `<beforePlay>` | 打出前作用域 | - | 分段: <playBody>:打出, <beforeEnd>:前 |
| `<beforePlayed>` | 被打出前作用域 | - | 分段: <passive>:被, <playBody>:打出, <beforeEnd>:前 |
| `<beforePreparingStageStart>` | 准备阶段开始前 | - |  |
| `<beforeRecover>` | 回复前作用域 | - | 分段: <recoverBody>:回复, <beforeEnd>:前 |
| `<beforeRoundStart>` | 轮开始前 | - |  |
| `<beforeShow>` | 展示前作用域 | - | 分段: <showBody>:展示, <beforeEnd>:前 |
| `<beforeShown>` | 被展示前作用域 | - | 分段: <passive>:被, <showBody>:展示, <beforeEnd>:前 |
| `<beforeThrowingStageStart>` | 弃牌阶段开始前 | - |  |
| `<beforeTurnStart>` | 回合开始前 | - |  |
| `<beforeUse>` | 使用前作用域 | - | 分段: <useBody>:使用, <beforeEnd>:前 |
| `<beforeUsed>` | 被使用前作用域 | - | 分段: <passive>:被, <useBody>:使用, <beforeEnd>:前 |
| `<bonus-penalty>` | 奖惩 | - |  |
| `<bottom>` | 区域底作用域 | - | 分段: <bottomEnd>:底 |
| `<can>` | 可作用域 | - | 分段: <canHead>:可 |
| `<cancel>` | 取消 | - |  |
| `<cannot>` | (复合/分段) | - |  |
| `<cannotTarget>` | 无法指定作用域 | - | 分段: <cannotTargetHead>:无法, <passive>:被, <cannotTargetBody>:指定, <cannotTargetedBody>:成为, <as>:为, <cannotTargetEnd>:目标·无法指定 |
| `<cannotTo>` | 无法对作用域 | - | 分段: <cannotToHead>:无法对, <cannotToTarget>:目标·无法对 |
| `<card>` | 牌 | - |  |
| `<cardDefault>` | 牌·手牌或装备区内的牌 | `牌` |  |
| `<cardQuote>` | 【】作用域 | - | 分段: <cardQuoteLeft>:【, <cardQuoteRight>:】 |
| `<cardType>` | 类型 | - |  |
| `<changeTo>` | 改为 | - |  |
| `<characterSkill>` | 武将技能 | - |  |
| `<choose>` | 选择作用域 | - | 分段: <passive>:被, <chooseBody>:选择, <as>:为, <chooseRole>:选择者, <targetNumberLimit>:目标数限制, <targetLimit>:目标限制, <distanceLimit>:距离限制 |
| `<command>` | 指令 | - |  |
| `<compareRole>` | 拼点者 | - |  |
| `<comparedCard>` | 拼点牌 | - |  |
| `<comparison>` | 拼点作用域 | - | 分段: <reciprocalMark>:与, <comparisonEnd>:拼点, <comparisonInitiator>:发起者, <comparisonTarget>:目标·拼点, <comparisonEffect>:效果·拼点 |
| `<concluding>` | (复合/分段) | `true` |  |
| `<concludingStage>` | 结束阶段 | - |  |
| `<concludingStageProcess>` | (复合/分段) | - |  |
| `<condition>` | 条件 | - |  |
| `<coordination>` | 并列作用域 | - | 分段: <stativeCoordination>:且, <nominalCoordination>:与·名词并列, <actionCoordination>:并 |
| `<counts>` | 数作用域 | - | 分段: <countsEnd>:数 |
| `<cure>` | 治疗作用域 | - | 分段: <directedMark>:对, <dealtBody>:造成, <takeBody>:受到, <cureEnd>:治疗, <cureRole>:来源·治疗, <curedRole>:受疗者, <cureValue>:治疗值 |
| `<current>` | 本作用域 | - | 分段: <currentHead>:本 |
| `<currentTick>` | 当前时机 | - |  |
| `<currentTurnRole>` | 当前回合角色 | - |  |
| `<damage>` | 伤害作用域 | - | 分段: <directedMark>:对, <dealtBody>:造成, <takeBody>:受到, <damageEnd>:伤害, <damageRole>:来源·伤害, <damagedRole>:受伤者, <damageValue>:伤害值 |
| `<damaged>` | 受伤 | - |  |
| `<dead>` | 死亡·形容词 | `死亡` |  |
| `<deadRole>` | 死亡角色 | - |  |
| `<dealing>` | (复合/分段) | `true` |  |
| `<dealingStage>` | 判定阶段 | - |  |
| `<dealingStageProcess>` | (复合/分段) | - |  |
| `<deemAs>` | 视为 | - |  |
| `<die>` | 死亡作用域 | - | 分段: <dieEnd>:死亡, <dieRole>:死者 |
| `<discard>` | 弃置作用域 | - | 分段: <passive>:被, <discardBody>:弃置, <discardBody2>:弃, <discardRole>:弃置者, <discardedCard>:被弃牌 |
| `<discardPile>` | 弃牌堆 | - |  |
| `<distance>` | 距离作用域 | - | 分段: <reciprocalMark>:与, <distanceEnd>:距离 |
| `<dominatorSkill>` | (复合/分段) | - |  |
| `<draw>` | 摸牌作用域 | - | 分段: <drawHead>:摸, <drawEnd>:牌·摸牌, <drawer>:摸牌者, <drawQuantity>:摸牌数 |
| `<dying>` | 濒死作用域 | - | 分段: <dyingEnd>:濒死, <dyingRole>:濒死者 |
| `<each>` | 各作用域 | - | 分段: <eachHead>:各 |
| `<elseRole>` | 其他角色 | - |  |
| `<equipArea>` | 装备区 | - |  |
| `<equipmentSkill>` | 装备技能 | - |  |
| `<event>` | 事件 | - |  |
| `<every>` | 每作用域 | - | 分段: <everyHead>:每 |
| `<except>` | 否则作用域 | - | 分段: <exceptHead>:否则 |
| `<face>` | 向置作用域 | - | 分段: <passive>:被, <faceBody>:向置, <faceBody1>:向, <faceRole>:向置者, <facedCard>:被向置牌 |
| `<fewer>` | 少于作用域 | - | 分段: <fewerHead>:少于 |
| `<for>` | (复合/分段) | - |  |
| `<forOrAgainst>` | 向背 | - |  |
| `<formula>` | 公式 | - |  |
| `<game>` | (复合/分段) | - |  |
| `<getting>` | (复合/分段) | `true` |  |
| `<gettingStage>` | 摸牌阶段 | - |  |
| `<gettingStageProcess>` | (复合/分段) | - |  |
| `<greater>` | 大于作用域 | - | 分段: <greaterHead>:大于 |
| `<hand>` | 手牌区 | - |  |
| `<handCard>` | 手牌 | - |  |
| `<handLimit>` | 手牌上限 | - |  |
| `<health>` | (复合/分段) | - |  |
| `<healthLimit>` | 体力上限 | - |  |
| `<horizontal>` | (复合/分段) | - |  |
| `<if>` | 若作用域 | - | 分段: <ifHead>:若, <ifBody>:则, <else>:反之 |
| `<illegal>` | 非法 | - |  |
| `<inArea>` | 在区域内作用域 | - | 分段: <inHead>:在, <inEnd>:内 |
| `<inGame>` | (复合/分段) | - |  |
| `<inGameBool>` | (复合/分段) | - |  |
| `<inReach>` | 在范围内作用域 | - | 分段: <inHead>:在, <inReachEnd>:范围内 |
| `<inTicking>` | 于时段内作用域 | - | 分段: <inTickingHead>:于, <inEnd>:内 |
| `<inTurn>` | 依次作用域 | - | 分段: <inTurnHead>:依次 |
| `<inherentActingStage>` | 固有出牌阶段 | - |  |
| `<inherentConcludingStage>` | 固有结束阶段 | - |  |
| `<inherentDealingStage>` | 固有判定阶段 | - |  |
| `<inherentGettingStage>` | 固有摸牌阶段 | - |  |
| `<inherentPreparingStage>` | 固有准备阶段 | - |  |
| `<inherentStage>` | 固有阶段 | - |  |
| `<inherentThrowingStage>` | 固有弃牌阶段 | - |  |
| `<initialHandLimit>` | 手牌上限初值 | - |  |
| `<least>` | 最少作用域 | - | 分段: <leastHead>:最少 |
| `<legal>` | 合法 | - |  |
| `<less>` | 小于作用域 | - | 分段: <lessHead>:小于 |
| `<liveStatus>` | 存亡 | - |  |
| `<living>` | 存活 | - |  |
| `<lockedSkill>` | 锁定技 | - |  |
| `<loseComparison>` | 负 | - |  |
| `<loseComparisonPoint>` | 负点 | - |  |
| `<loseComparisonRole>` | 负方 | - |  |
| `<loss>` | 流失作用域 | - | 分段: <lossBody>:流失, <lossRole>:流失者, <lossValue>:流失值 |
| `<lostHealth>` | (复合/分段) | - |  |
| `<lyingArea>` | (复合/分段) | - |  |
| `<make>` | 令作用域 | - | 分段: <makeHead>:令 |
| `<max>` | 最大作用域 | - | 分段: <maxHead>:最大 |
| `<min>` | 最小作用域 | - | 分段: <minHead>:最小 |
| `<more>` | 多于作用域 | - | 分段: <moreHead>:多于 |
| `<most>` | 最多作用域 | - | 分段: <mostHead>:最多 |
| `<move>` | 移动作用域 | - | 分段: <passive>:被, <placeBody>:置于, <moveBody0>:移置, <moveBody1>:移动, <moveBody2>:移出, <moveBody3>:失去, <moveBody4>:置入, <moveBody5>:获得, <moveRole>:移置者, <movedCard>:目标牌, <movedInArea>:目标区域, <movedAtPosition>:目标位置 |
| `<nextSeat>` | 下家作用域 | - | 分段: <nextSeatHead>:下, <seatEnd>:家 |
| `<numberLimit>` | 次数限制 | - |  |
| `<numberLimiting>` | 限次作用域 | - | 分段: <numberLimitingHead>:限, <numberLimitingEnd>:次 |
| `<object>` | 对象 | - |  |
| `<objectInArea>` | (复合/分段) | - |  |
| `<offset>` | 抵消作用域 | - | 分段: <offsetEnd>:抵消, <offsetTarget>:目标·抵消 |
| `<operation>` | 操作 | - |  |
| `<or>` | 或作用域 | - | 分段: <orBody>:或 |
| `<outArea>` | 在区域外作用域 | - | 分段: <inHead>:在, <outAreaEnd>:外 |
| `<outGame>` | (复合/分段) | - |  |
| `<pile>` | 牌堆 | - |  |
| `<play>` | 打出作用域 | - | 分段: <passive>:被, <playBody>:打出, <player>:打出者, <playTarget>:目标·打出, <playedPhysicalCard>:对应实体牌·打出, <playedCard>:被打出牌, <playEffect>:效果·打出 |
| `<plus>` | 和作用域 | - | 分段: <reciprocalMark>:与, <plusBody>:加, <plusEnd>:和, <addend>:加数 |
| `<point>` | 点数 | - |  |
| `<polarity>` | (复合/分段) | - |  |
| `<position>` | 位置 | - |  |
| `<preclude>` | 排除 | - |  |
| `<preparing>` | (复合/分段) | `true` |  |
| `<preparingStage>` | 准备阶段 | - |  |
| `<preparingStageProcess>` | (复合/分段) | - |  |
| `<previousSeat>` | 上家作用域 | - | 分段: <previousSeatHead>:上, <seatEnd>:家 |
| `<priority>` | 优先级 | - |  |
| `<procedure>` | 程序 | - |  |
| `<procedureTick>` | 程序时机 | - |  |
| `<procedureTrigger>` | 程序触发结构 | - |  |
| `<process>` | 流程 | - |  |
| `<pronoun1>` | (复合/分段) | - |  |
| `<pronoun2>` | (复合/分段) | - |  |
| `<pronoun3>` | (复合/分段) | - |  |
| `<quote>` | ()作用域 | - | 分段: <quoteLeft>:(, <quoteRight>:) |
| `<reach>` | (复合/分段) | - |  |
| `<recover>` | 回复作用域 | - | 分段: <recoverBody>:回复, <recoverRole>:回复者, <recoverValue>:回复值 |
| `<remove>` | 去除作用域 | - | 分段: <passive>:被, <removeBody>:去除, <remover>:去除者, <initialTarget>:原目标, <removeTarget>:目标·去除 |
| `<role>` | 角色 | - |  |
| `<roleDefault>` | 角色·存活角色 | `角色` |  |
| `<roleSeated>` | 位作用域 | - | 分段: <roleSeatedBody>:位 |
| `<round>` | (复合/分段) | - |  |
| `<roundProcess>` | (复合/分段) | - |  |
| `<rounds>` | 轮数 | - |  |
| `<seat>` | 座位 | - |  |
| `<seatOrder>` | 位次 | - |  |
| `<self>` | 自己 | - |  |
| `<show>` | 展示作用域 | - | 分段: <showBody>:展示, <showRole>:展示者, <shownCard>:被展示牌 |
| `<skill>` | 技能 | - |  |
| `<skillQuote>` | 〖〗作用域 | - | 分段: <skillQuoteLeft>:〖, <skillQuoteRight>:〗 |
| `<stage>` | (复合/分段) | - |  |
| `<stageProcess>` | (复合/分段) | - |  |
| `<status>` | 状态 | - |  |
| `<theLeast>` | 唯一最少作用域 | - | 分段: <theLeastHead>:唯一最少 |
| `<theMax>` | 唯一最大作用域 | - | 分段: <theMaxHead>:唯一最大 |
| `<theMin>` | 唯一最小作用域 | - | 分段: <theMinHead>:唯一最小 |
| `<theMost>` | 唯一最多作用域 | - | 分段: <theMostHead>:唯一最多 |
| `<this>` | 此作用域 | - | 分段: <thisHead>:此 |
| `<throwing>` | (复合/分段) | `true` |  |
| `<throwingStage>` | 弃牌阶段 | - |  |
| `<throwingStageProcess>` | (复合/分段) | - |  |
| `<tick>` | 时机 | - |  |
| `<tickLimit>` | 时机限制 | - |  |
| `<ticking>` | 时段 | - |  |
| `<tickingLimit>` | (复合/分段) | - |  |
| `<tickingTimeLimit>` | 时段与次数限制 | - |  |
| `<together>` | (复合/分段) | - |  |
| `<top>` | 区域顶作用域 | - | 分段: <topEnd>:顶 |
| `<treatmentArea>` | 处理区 | - |  |
| `<trickCard>` | 锦囊牌 | - |  |
| `<turn>` | (复合/分段) | - |  |
| `<turnProcess>` | (复合/分段) | - |  |
| `<undamaged>` | 未受伤 | - |  |
| `<use>` | 使用作用域 | - | 分段: <directedMark>:对, <passive>:被, <useBody>:使用, <user>:使用者, <useTarget>:目标·使用, <usedPhysicalCard>:对应实体牌·使用, <usedCard>:被使用牌 |
| `<vertical>` | (复合/分段) | - |  |
| `<verticalOrHorizontal>` | 纵横 | - |  |
| `<visible>` | 可见作用域 | - | 分段: <directedMark>:对, <visibleBody>:可见 |
| `<when>` | 当作用域 | - | 分段: <whenHead>:当 |
| `<whenActingStageFinish>` | 出牌阶段结束时 | - |  |
| `<whenActingStageStart>` | 出牌阶段开始时 | - |  |
| `<whenAffect>` | 生效时 | - |  |
| `<whenBack>` | 背置时作用域 | - | 分段: <backBody>:背置, <whenEnd>:时 |
| `<whenBacked>` | 被背置时作用域 | - | 分段: <passive>:被, <backBody>:背置, <whenEnd>:时 |
| `<whenComparison>` | 拼点时 | - |  |
| `<whenConcludingStageFinish>` | 结束阶段结束时 | - |  |
| `<whenConcludingStageStart>` | 结束阶段开始时 | - |  |
| `<whenCure>` | 造成治疗时作用域 | - | 分段: <dealtBody>:造成, <cureEnd>:治疗, <whenEnd>:时 |
| `<whenCured>` | 受到治疗时作用域 | - | 分段: <takeBody>:受到, <cureEnd>:治疗, <whenEnd>:时 |
| `<whenDamage>` | 造成伤害时作用域 | - | 分段: <dealtBody>:造成, <damageEnd>:伤害, <whenEnd>:时 |
| `<whenDamaged>` | 受到伤害时作用域 | - | 分段: <takeBody>:受到, <damageEnd>:伤害, <whenEnd>:时 |
| `<whenDealingStageFinish>` | 判定阶段结束时 | - |  |
| `<whenDealingStageStart>` | 判定阶段开始时 | - |  |
| `<whenDie>` | 死亡时 | - |  |
| `<whenDiscard>` | 弃置时作用域 | - | 分段: <discardBody>:弃置, <whenEnd>:时 |
| `<whenDiscarded>` | 被弃置时作用域 | - | 分段: <passive>:被, <discardBody>:弃置, <whenEnd>:时 |
| `<whenDraw>` | 摸牌时 | - |  |
| `<whenDying>` | 濒死时 | - |  |
| `<whenEnteringDying>` | 陷入濒死时 | - |  |
| `<whenExitingDying>` | 脱离濒死时 | - |  |
| `<whenFace>` | 向置时作用域 | - | 分段: <faceBody>:向置, <whenEnd>:时 |
| `<whenFaced>` | 被向置时作用域 | - | 分段: <passive>:被, <faceBody>:向置, <whenEnd>:时 |
| `<whenGameStart>` | 局开始时 | - |  |
| `<whenGettingStageFinish>` | 摸牌阶段结束时 | - |  |
| `<whenGettingStageStart>` | 摸牌阶段开始时 | - |  |
| `<whenLoss>` | 流失时作用域 | - | 分段: <lossBody>:流失, <whenEnd>:时 |
| `<whenOffset>` | 抵消时 | - |  |
| `<whenPlace>` | 置于时作用域 | - | 分段: <patientMark>:将, <placeBody>:置于, <whenEnd>:时 |
| `<whenPlaced>` | 被置于时作用域 | - | 分段: <passive>:被, <placeBody>:置于, <whenEnd>:时 |
| `<whenPlay>` | 打出时作用域 | - | 分段: <playBody>:打出, <whenEnd>:时 |
| `<whenPlayed>` | 被打出时作用域 | - | 分段: <passive>:被, <playBody>:打出, <whenEnd>:时 |
| `<whenPreparingStageFinish>` | 准备阶段结束时 | - |  |
| `<whenPreparingStageStart>` | 准备阶段开始时 | - |  |
| `<whenRecover>` | 回复时作用域 | - | 分段: <recoverBody>:回复, <whenEnd>:时 |
| `<whenRoundFinish>` | 轮结束时 | - |  |
| `<whenRoundStart>` | 轮开始时 | - |  |
| `<whenShow>` | 展示时作用域 | - | 分段: <showBody>:展示, <whenEnd>:时 |
| `<whenShown>` | 被展示时作用域 | - | 分段: <passive>:被, <showBody>:展示, <whenEnd>:时 |
| `<whenThrowingStageFinish>` | 弃牌阶段结束时 | - |  |
| `<whenThrowingStageStart>` | 出牌阶段开始时 | - |  |
| `<whenTurnFinish>` | 回合结束时 | - |  |
| `<whenTurnStart>` | 回合开始时 | - |  |
| `<whenUse>` | 使用时作用域 | - | 分段: <useBody>:使用, <whenEnd>:时 |
| `<whenUsed>` | 被使用时作用域 | - | 分段: <passive>:被, <useBody>:使用, <whenEnd>:时 |
| `<winComparison>` | 胜 | - |  |
| `<winComparisonPoint>` | 胜点 | - |  |
| `<winComparisonRole>` | 胜方 | - |  |
| `<yang>` | 阳 | - |  |
| `<yin>` | 阴 | - |  |
| `<you>` | 你 | - |  |
| `<equaling>` | (动态术语) | - | 见 Dynamic Terms 详情 |
| `<include>` | (动态术语) | - | 见 Dynamic Terms 详情 |
| `<roundUp>` | (动态术语) | - | 见 Dynamic Terms 详情 |

## 2. 技能库 (Skills)

用于辅助判断代码中涉及技能逻辑的部分：

### [衍生物] 允中
> **内容**: <actingStageCC>一</actingStageCC>，<youCanCC><or><makeC><discard><discardRole class="irreplaceable"><mostC><handCard></handCard></mostC>的<roleDefault></roleDefault></discardRole><eachC><discardedCardC><choose><targetACardCC></targetACardCC></choose></discardedCardC></discard></eachC></makeC><orBody></orBody><makeC><draw><drawer class="irreplaceable"><leastC><handCard></handCard></leastC>的<roleDefault></roleDefault></drawer><eachC><drawQuantityC>一张</drawQuantityC></draw></eachC></makeC></or></youCanCC>。
> **关联角色ID**: 125

### [衍生物] 唯识
> **内容**: <ticklimit class="irreplaceable"><whenactingstagestart></whenactingstagestart></ticklimit>，<you></you><can><canhead></canhead><comparison><reciprocalmark></reciprocalmark><comparisontarget class="irreplaceable"><targetnumberlimit class="irreplaceable"><anynumber></anynumber>名</targetnumberlimit><roledefault></roledefault></comparisontarget><comparisonend></comparisonend></comparison></can>，<if><ifhead></ifhead><you></you><wincomparison></wincomparison></if>，<comparerole></comparerole><each><eachhead></eachhead><can><canhead></canhead></can><use><usebody></usebody><usedcard class="irreplaceable"><choose><targetnumberlimit class="irreplaceable">一张</targetnumberlimit><targetlimit class="irreplaceable"><comparedcard></comparedcard></targetlimit></choose></usedcard></use></each>。若如此做，<current><currenthead></currenthead><turn></turn></current><you></you>的<point></point><greater><greaterhead></greaterhead><max><maxhead></maxhead><losecomparisonpoint></losecomparisonpoint></max></greater>的<handcard></handcard>的<affect><effect></effect></affect><deemas></deemas><cardquote><cardquoteleft></cardquoteleft><deliver></deliver><cardquoteright></cardquoteright></cardquote>。
> **关联角色ID**: 8

### [衍生物] 泊心
> **内容**: <tickingLimitCC><gettingStage></gettingStage></tickingLimitCC>，<youCanCC>改为<drawC><drawQuantity class="irreplaceable">x张</drawQuantity>(“x”为其他角色数与你已失去体力值和，至多为5)</drawC></youCanCC>。若如此做，<crtTurnCC></crtTurnCC><youUseC><card></card></youUseC>无法指定<self></self>为目标。
> **关联角色ID**: 11

### [衍生物] 狐鸣
> **内容**: <ticklimit class="irreplaceable"><when><whenhead></whenhead>一名<roledefault></roledefault><afterdie></afterdie></when></ticklimit>，<you></you><can><canhead></canhead><discard class="irreplaceable"><discardbody></discardbody><discardedcard class="irreplaceable"><choose><targetnumberlimit class="irreplaceable">一张</targetnumberlimit><targetlimit class="irreplaceable"><yin></yin><trickcard></trickcard></targetlimit></choose></discardedcard></discard><recover><recoverbody></recoverbody><recovervalue class="irreplaceable">一点</recovervalue><or><health></health><orbody></orbody><healthlimit></healthlimit></or></recover></can>。
> **关联角色ID**: 2

### [衍生物] 玄德
> **内容**: <lockedSkill></lockedSkill>，<tickingLimitCC><preparingStage></preparingStage></tickingLimitCC>，<youDrawCC><equalingC><lostHealth epithet="1"></lostHealth epithet="1">一半(<roundUp><roundUp0></roundUp0></roundUp>)</equalingC>的</youDrawCC>。
> **关联角色ID**: 125

### [衍生物] 筹策
> **内容**: <lockedskill></lockedskill>，<ticklimit class="irreplaceable"><when><whenhead></whenhead><you></you><whenuse><usebody></usebody><use><usedcard class="irreplaceable"><use><usetarget></usetarget></use><include><include0></include0><elserole></elserole></include>的<trickcard></trickcard></usedcard></use><whenend></whenend></whenuse></when></ticklimit>，<draw><drawhead></drawhead><drawquantity class="irreplaceable">一张</drawquantity><drawend></drawend></draw>。
> **关联角色ID**: 6

### [衍生物] 自然
> **内容**: <lockedskill></lockedskill>，<ticklimit class="irreplaceable"><whenactingstagefinish></whenactingstagefinish></ticklimit>，<use><user class="irreplaceable"><you></you></user><usebody></usebody><usedcard class="irreplaceable"><choose><targetnumberlimit class="irreplaceable">一张</targetnumberlimit><targetlimit class="irreplaceable"><handcard></handcard></targetlimit></choose></usedcard></use>，<except><excepthead></excepthead>，<draw><drawhead></drawhead><drawquantity class="irreplaceable">一张</drawquantity><drawend></drawend></draw></except>。
> **关联角色ID**: 9

### [衍生物] 观复
> **内容**: <ticklimit class="irreplaceable"><whenactingstagestart></whenactingstagestart></ticklimit>，<you></you><can><canhead></canhead><coordination><discard class="irreplaceable"><discardbody></discardbody><discardedcard class="irreplaceable"><pronoun1>所有<handcard></handcard></pronoun1></discardedcard></discard><actioncoordination></actioncoordination><draw><drawhead></drawhead><drawquantity class="irreplaceable"><pronoun1>等量</pronoun1></drawquantity><drawend></drawend></draw></coordination></can>。
> **关联角色ID**: 9

### [衍生物] 鸿志
> **内容**: <lockedskill></lockedskill>，<ticklimit class="irreplaceable"><when><whenhead></whenhead>一名<roledefault></roledefault><whenenteringdying></whenenteringdying></when></ticklimit>，<draw><drawer class="irreplaceable"><you></you></drawer><drawhead></drawhead><drawquantity class="irreplaceable">两张</drawquantity><drawend></drawend></draw>；<ticklimit class="irreplaceable"><when><whenhead></whenhead>一名<roledefault></roledefault><afterdie></afterdie></when></ticklimit>，<you></you><or><draw><drawhead></drawhead><drawquantity class="irreplaceable">一张</drawquantity><drawend></drawend></draw><orbody></orbody><activate><activatebody></activatebody><skillquote><skillquoteleft></skillquoteleft><characterskillelement class="狐鸣"></characterskillelement><skillquoteright></skillquoteright></skillquote></activate></or>。
> **关联角色ID**: 2

### [普通] 允中
> **内容**: <tickingLimitC><actingStage></actingStage></tickingLimit><numberLimitC>一</numberLimitC></tickingLimitC>，<you></you><canC><or><makeC><discard><discardRole class="irreplaceable"><choose><targetNumberLimit class="irreplaceable"><anyNumber></anyNumber>名</targetNumberLimit><targetLimit class="irreplaceable"><mostC><handCard></handCard></mostC>的<roleDefault></roleDefault></targetLimit></choose></discardRole><eachC><discardBody></discardBody><discardedCard class="replaceable"><choose><targetNumberLimit class="irreplaceable">一张</targetNumberLimit><cardDefault></cardDefault></choose></discardedCard></discard></eachC></makeC><orBody></orBody><makeC><draw><drawer class="irreplaceable"><choose><targetNumberLimit class="irreplaceable"><anyNumber></anyNumber>名</targetNumberLimit><targetLimit class="irreplaceable"><leastC><handCard></handCard></leastC>的<roleDefault></roleDefault></targetLimit></choose></drawer><eachC><drawQuantityC>一张</drawQuantityC></draw></eachC></makeC></or></canC>。
> **关联角色ID**: 125

### [普通] 玄德
> **内容**: 锁定技，<tickingLimitC><preparingStage></preparingStage></tickingLimitC>，<youDrawCC><equalingC><lostHealth epithet='1'></lostHealth epithet='1'>+1的一半(<roundUp><roundUp0></roundUp0></roundUp>)</equalingC>的</youDrawCC>。
> **关联角色ID**: 125

### [普通] 鸿志
> **内容**: <lockedskill></lockedskill>，<ticklimit class="irreplaceable"><when><whenhead></whenhead>一名<roledefault></roledefault><whenenteringdying></whenenteringdying></when></ticklimit>，<draw><drawer class="irreplaceable"><you></you></drawer><drawhead></drawhead><drawquantity class="irreplaceable">两张</drawquantity><drawend></drawend></draw>；<ticklimit class="irreplaceable"><when><whenhead></whenhead>一名<roledefault></roledefault><whendie></whendie></when></ticklimit>，<you></you><coordination><draw><drawhead></drawhead><drawquantity class="irreplaceable">一张</drawquantity><drawend></drawend></draw><actioncoordination></actioncoordination>增加一点<handlimit></handlimit></coordination>。
> **关联角色ID**: 2

### [君主] 允中
> **内容**: <tickingLimitC><actingStage></actingStage></tickingLimit><numberLimitC>两</numberLimitC></tickingLimitC>，<you></you><canC><or><makeC><discard><discardRole class="irreplaceable"><choose><targetNumberLimit class="irreplaceable"><anyNumber></anyNumber>名</targetNumberLimit><targetLimit class="irreplaceable"><mostC><handCard></handCard></mostC>的<roleDefault></roleDefault></targetLimit></choose></discardRole><eachC><discardBody></discardBody><discardedCard class="irreplaceable"><choose class="irreplaceable"><targetNumberLimit class="irreplaceable">一张</targetNumberLimit><cardDefault></cardDefault></choose></discardedCard></discard></eachC></makeC><orBody></orBody><makeC><draw><drawer class="irreplaceable"><choose><targetNumberLimit class="irreplaceable"><anyNumber></anyNumber>名</targetNumberLimit><targetLimit class="irreplaceable"><leastC><handCard></handCard></leastC>的<roleDefault></roleDefault></targetLimit></choose></drawer><eachC><drawQuantityC>一张</drawQuantityC></draw></eachC></makeC></or></canC>。
> **关联角色ID**: 125

### [君主] 玄德
> **内容**: 锁定技，<tickingLimitC><preparingStage></preparingStage></tickingLimitC>，<you></you><makeC><draw><drawer class="irreplaceable"><choose><targetNumberLimit class="irreplaceable"><anyNumber></anyNumber>名</targetNumberLimit><targetLimit class="irreplaceable"><roleDefault></roleDefault></targetLimit></choose></drawer><drawQuantityC>共x(“x”为<you></you><lostHealth epithet='1'></lostHealth epithet='1'>+1的一半，<roundUp><roundUp0></roundUp0></roundUp>)的</drawQuantityC></draw></makeC>；<you></you>的<handLimit></handLimit>+x。
> **关联角色ID**: 125

## 3. 角色列表 (Characters)

| ID | 姓名 | 称号 | 体力 | 势力 |
| --- | --- | --- | --- | --- |
| 2 | 陈胜/吴广 | 鴻鵠之志 | 4 | 朱雀 |
| 6 | 田忌/孙膑 | 東面朝齊 | 4 | 朱雀 |
| 8 | 玄奘 | 遠紹如來 | 4 | 青龙 |
| 9 | 李耳 | 道法自然 | 3 | 青龙 |
| 11 | 列御寇 | 衝虚真人 | 3 | 青龙 |
| 125 | 姚重华 | 黜陟幽明 | 4 | 青龙 |

